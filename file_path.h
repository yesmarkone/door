/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1268-1464. */
#ifndef DOOR_FILE_PATH_H
#define DOOR_FILE_PATH_H

static __always_inline int check(struct file *file, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *path_scratch;
    long len;

    if (task_is_exempt()) {
        /* Do not retain an older pending exec event for an exempt task. */
        if (op == OP_EXEC) {
            __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_map_delete_elem(&wax_pending_execs, &pid);
        }
        return 0;
    }
    path_scratch = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!path_scratch) return 0;
    path_scratch->path[0] = '\0';
    len = bpf_d_path(&file->f_path, path_scratch->path, PATH_LEN);
    if (len <= 0) return 0;
    if (op == OP_EXEC) {
        __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_map_delete_elem(&wax_pending_execs, &pid);
    }
    return check_policy(path_scratch->path, (__u32)len - 1, op);
}

/* Resolve "parent directory path" + "/" + "dentry name" into the shared path
 * scratch and run the policy on it. Used by
 * unlink/rmdir/mkdir/symlink/link/mknod/rename,
 * whose hooks receive the target as a (parent path, dentry) pair. */
static __always_inline int check_dir_dentry(const struct path *dir,
                                            struct dentry *dentry, __u8 op)
{
    __u32 zero = 0, off;
    struct file_path_scratch *ps;
    const unsigned char *name;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)dir, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    off = (__u32)len - 1;                       /* index of the NUL */
    if (off >= PATH_LEN) return 0;
    /* barrier_var keeps clang from re-deriving these offsets from len, which
     * would drop the masks the verifier needs to see. */
    barrier_var(off);
    off &= PATH_LEN - 1;
    if (off > 0) {
        __u32 prev = off - 1;

        barrier_var(prev);
        prev &= PATH_LEN - 1;
        if (ps->path[prev] == '/') off = prev;  /* parent is "/" */
    }
    ps->path[off] = '/';
    name = BPF_CORE_READ(dentry, d_name.name);
    len = bpf_probe_read_kernel_str(&ps->path[off + 1], PATH_LEN, name);
    if (len <= 0) return 0;
    /* off + 1 leading bytes plus len - 1 component bytes. This is the one
     * producer that can exceed PATH_LEN, which only suffix rules care about;
     * they decline to match a path they cannot see the end of. */
    return check_policy(ps->path, off + (__u32)len, op);
}

/* Hooks that receive the target as a struct path resolve it directly. */
static __always_inline int check_path_op(const struct path *p, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *ps;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)p, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * inode_setattr only receives a dentry, so the path is rebuilt by walking
 * d_parent toward the filesystem root, writing components right-to-left.
 * The result lacks the mount prefix for files on non-root mounts; rules are
 * matched against the path as seen from that filesystem's root.
 */
struct dentry_walk_ctx {
    struct dentry *d;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

static long dentry_walk_cb(__u32 i, void *data)
{
    struct dentry_walk_ctx *ctx = data;
    struct dentry *d = ctx->d, *parent;
    const unsigned char *name;
    __u32 pos, sz;
    long len;

    if (!d) {
        ctx->failed = 1;
        return 1;
    }
    parent = BPF_CORE_READ(d, d_parent);
    if (parent == d) {
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(d, d_name.name);
    len = bpf_probe_read_kernel_str(ctx->s->name, PATH_LEN, name);
    if (len <= 1) {
        ctx->failed = 1;
        return 1;
    }
    sz = (__u32)len - 1;                        /* component bytes, no NUL */
    if (sz >= PATH_LEN || ctx->pos < sz + 1) {  /* out of path budget */
        ctx->failed = 1;
        return 1;
    }
    pos = ctx->pos - (sz + 1);
    if (pos >= PATH_LEN) {                      /* bound for the verifier */
        ctx->failed = 1;
        return 1;
    }
    ctx->s->build[pos] = '/';
    if (bpf_probe_read_kernel(&ctx->s->build[pos + 1], sz, ctx->s->name) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->pos = pos;
    ctx->d = parent;
    return 0;
}

static __always_inline int check_dentry_op(struct dentry *dentry, __u8 op)
{
    __u32 zero = 0;
    struct dentry_walk_scratch *s;
    struct file_path_scratch *ps;
    struct dentry_walk_ctx ctx;
    long len;

    if (task_is_exempt()) return 0;
    s = bpf_map_lookup_elem(&wax_dentry_walk_scratch_map, &zero);
    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!s || !ps) return 0;
    s->build[PATH_LEN] = '\0';
    ctx = (struct dentry_walk_ctx){ .d = dentry, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_DENTRY_DEPTH, dentry_walk_cb, &ctx, 0);
    /* Allow rather than mis-match on an incomplete (too deep/long) walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return 0;
    if (ctx.pos == PATH_LEN) {                  /* dentry was the root itself */
        ps->path[0] = '/';
        ps->path[1] = '\0';
        len = 2;
    } else if ((len = bpf_probe_read_kernel_str(ps->path, PATH_LEN,
                                                &s->build[ctx.pos])) <= 0) {
        return 0;
    }
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * Strict LSM verifiers (e.g. RHEL 9.8, kernel 5.14.0-687) require every hook to
 * return a value provably within [-4095, 0]. Two things are needed. First, the
 * hooks return `long` so clang sign-extends the result into the full 64-bit R0:
 * an `int` return emits a 32-bit move that zero-extends, turning a negative
 * errno (e.g. -EACCES) into a large positive value the verifier rejects.
 * Second, lsm_ret() clamps the value with signed comparisons so the verifier
 * can bound smin/smax to exactly [-4095, 0]. Valid results (0, -EACCES, or a
 * prior hook's errno) pass through unchanged. Older 5.14 verifiers (RHEL 9.5)
 * accepted the un-clamped `int` form, so this only tightens portability.
 */
static __always_inline long lsm_ret(long r)
{
    /* barrier_var keeps clang from proving the value's range at compile time
     * (e.g. that check() only yields 0 or -EACCES) and then dropping a clamp or
     * lowering it to a 32-bit subregister compare the verifier cannot tie back
     * to the returned register. Forcing an opaque 64-bit value before each
     * signed compare makes the verifier track smin/smax on the exact register
     * that is returned. */
    barrier_var(r);
    if (r < -4095)
        r = -4095;
    barrier_var(r);
    if (r > 0)
        r = 0;
    barrier_var(r);
    return r;
}

#endif /* DOOR_FILE_PATH_H */
