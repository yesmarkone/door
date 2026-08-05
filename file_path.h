/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1268-1464, before the split. */
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

/* inode_setattr only receives a dentry; the path comes from the d_parent walk
 * in file_walk.h, with the mount-prefix caveat documented there. */
static __always_inline int check_dentry_op(struct dentry *dentry, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *ps;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!ps) return 0;
    len = walk_dentry_path(dentry, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    return check_policy(ps->path, (__u32)len - 1, op);
}

/* Judge an open file whose path cannot come from bpf_d_path, because the hook
 * is not a sleepable one. walk_file_path() in file_walk.h explains which hooks
 * those are and why the mount chain has to be walked rather than the dentry
 * chain alone; check_policy resolves the process image the same way, which is
 * what the walk argument selects. */
static __always_inline int check_file_walk_op(struct file *file, __u8 op,
                                              __u8 quiet_s)
{
    __u32 zero = 0;
    struct file_path_scratch *ps;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!ps) return 0;
    len = walk_file_path(file, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    return check_policy_walk(ps->path, (__u32)len - 1, op, quiet_s);
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
