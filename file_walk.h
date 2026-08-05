/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers.
 *
 * Turning kernel objects into path strings, and nothing else — no policy, no
 * verdict, no events. That separation is what lets these run before
 * file_policy.h, which is where check_policy needs them: resolving the current
 * process image is part of every check, and in a hook where bpf_d_path is
 * refused it has to come from here.
 *
 * Lifted out of door/file_path.h, which keeps the check_* wrappers that pair a
 * resolved path with check_policy. */
#ifndef DOOR_FILE_WALK_H
#define DOOR_FILE_WALK_H

/* Write "/" + this dentry's name immediately to the left of *pos in the build
 * buffer and move *pos to the start of what was written. Shared by both walkers
 * below; the bounds here are what the verifier reads to prove every build[]
 * access stays inside PATH_LEN, so the masks are not decoration. Returns -1 when
 * the name is unreadable or the remaining budget is too small, which both
 * callers turn into a fail-open. */
static __always_inline int prepend_component(struct dentry_walk_scratch *s,
                                             struct dentry *d, __u32 *pos)
{
    const unsigned char *name;
    __u32 p, sz;
    long len;

    name = BPF_CORE_READ(d, d_name.name);
    len = bpf_probe_read_kernel_str(s->name, PATH_LEN, name);
    if (len <= 1) return -1;
    sz = (__u32)len - 1;                    /* component bytes, no NUL */
    if (sz >= PATH_LEN || *pos < sz + 1) return -1;   /* out of path budget */
    p = *pos - (sz + 1);
    if (p >= PATH_LEN) return -1;           /* bound for the verifier */
    s->build[p] = '/';
    if (bpf_probe_read_kernel(&s->build[p + 1], sz, s->name) < 0) return -1;
    *pos = p;
    return 0;
}

/* Copy the finished right-to-left build buffer out to a caller's buffer, and
 * report its length INCLUDING the NUL, matching what bpf_d_path returns so the
 * two resolution paths are interchangeable at the call site. 0 means the walk
 * did not produce a usable path; every caller fails open on that. */
static __always_inline long emit_walked_path(struct dentry_walk_scratch *s,
                                             __u32 pos, __u8 done, __u8 failed,
                                             char *out, __u32 out_len)
{
    /* Allow rather than mis-match on an incomplete (too deep/long) walk. */
    if (!done || failed || pos > PATH_LEN) return 0;
    if (pos == PATH_LEN) {                  /* the root itself */
        out[0] = '/';
        out[1] = '\0';
        return 2;
    }
    return bpf_probe_read_kernel_str(out, out_len, &s->build[pos]);
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

    if (!d) {
        ctx->failed = 1;
        return 1;
    }
    parent = BPF_CORE_READ(d, d_parent);
    if (parent == d) {
        ctx->done = 1;
        return 1;
    }
    if (prepend_component(ctx->s, d, &ctx->pos) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->d = parent;
    return 0;
}

static __always_inline long walk_dentry_path(struct dentry *dentry, char *out,
                                             __u32 out_len)
{
    __u32 zero = 0;
    struct dentry_walk_scratch *s;
    struct dentry_walk_ctx ctx;

    s = bpf_map_lookup_elem(&wax_dentry_walk_scratch_map, &zero);
    if (!s) return 0;
    s->build[PATH_LEN] = '\0';
    ctx = (struct dentry_walk_ctx){ .d = dentry, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_DENTRY_DEPTH, dentry_walk_cb, &ctx, 0);
    return emit_walked_path(s, ctx.pos, ctx.done, ctx.failed, out, out_len);
}

/*
 * Resolve an open file's absolute path WITHOUT bpf_d_path, by walking the same
 * two chains prepend_path() walks in fs/d_path.c: dentry -> d_parent up to the
 * mount root, then across to the mountpoint dentry in the parent mount, and
 * around again until a mount is its own parent.
 *
 * WHY THIS EXISTS, so nobody deletes it and calls bpf_d_path instead:
 *
 * bpf_d_path() is refused in lsm/file_permission. For BPF_PROG_TYPE_LSM the
 * kernel does NOT gate that helper on btf_allowlist_d_path — which does contain
 * security_file_permission, and is a red herring here — but on
 * bpf_lsm_is_sleepable_hook(), i.e. membership of the sleepable_lsm_hooks set.
 * bpf_lsm_file_open, bpf_lsm_inode_mknod and bpf_lsm_path_chmod are in that set;
 * bpf_lsm_file_permission is NOT, and the load fails with "helper call is not
 * allowed in probe". Verified against this kernel's BTF id sets, not inferred.
 *
 * The other way out would have been walk_dentry_path() above, which needs no
 * mount and is what inode_setattr uses. It is wrong here: it stops at the
 * filesystem root, so a directory on a separate mount resolves without its mount
 * prefix — /home/alice/private becomes /alice/private wherever /home is its own
 * filesystem, which is most enterprise hosts and exactly the shape read and list
 * rules are written in. A directory has to match the same string here that it
 * matches at file_open, or one rule cannot cover both, so the mount chain is not
 * optional and this walker crosses it.
 */
struct file_walk_ctx {
    struct dentry *d;
    struct mount *mnt;
    struct dentry *mnt_root;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

static long file_walk_cb(__u32 i, void *data)
{
    struct file_walk_ctx *ctx = data;
    struct dentry *d = ctx->d, *parent;
    struct mount *mnt = ctx->mnt, *mnt_parent;

    if (!d || !mnt) {
        ctx->failed = 1;
        return 1;
    }
    if (d == ctx->mnt_root) {
        /* Top of this filesystem. Step out to the directory it is mounted on
         * and keep prepending from there; when a mount is its own parent we
         * have reached the root of the namespace and the path is complete. */
        mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
        if (!mnt_parent || mnt_parent == mnt) {
            ctx->done = 1;
            return 1;
        }
        ctx->d = BPF_CORE_READ(mnt, mnt_mountpoint);
        ctx->mnt = mnt_parent;
        ctx->mnt_root = BPF_CORE_READ(mnt_parent, mnt.mnt_root);
        return 0;
    }
    parent = BPF_CORE_READ(d, d_parent);
    /* A dentry that is its own parent without being the mount root is
     * disconnected (deleted, or anonymous). Stop and take what we have rather
     * than claim a path we cannot vouch for. */
    if (!parent || parent == d) {
        ctx->done = 1;
        return 1;
    }
    if (prepend_component(ctx->s, d, &ctx->pos) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->d = parent;
    return 0;
}

static __always_inline long walk_file_path(struct file *file, char *out,
                                           __u32 out_len)
{
    __u32 zero = 0;
    struct dentry_walk_scratch *s;
    struct file_walk_ctx ctx;
    struct vfsmount *vfsmnt;
    struct mount *mnt;

    if (!file) return 0;
    s = bpf_map_lookup_elem(&wax_dentry_walk_scratch_map, &zero);
    if (!s) return 0;
    vfsmnt = BPF_CORE_READ(file, f_path.mnt);
    if (!vfsmnt) return 0;
    /* container_of. struct vfsmount is embedded in struct mount, and the offset
     * is a CO-RE relocation so a kernel that reorders those fields still lands
     * on the right one. */
    mnt = (struct mount *)((char *)vfsmnt -
                           bpf_core_field_offset(struct mount, mnt));

    s->build[PATH_LEN] = '\0';
    ctx = (struct file_walk_ctx){
        .d = BPF_CORE_READ(file, f_path.dentry),
        .mnt = mnt,
        .mnt_root = BPF_CORE_READ(vfsmnt, mnt_root),
        .s = s,
        .pos = PATH_LEN,
    };
    /* One budget for components and mount crossings together. A path deep
     * enough to exhaust it fails open, as everywhere else in this file. */
    bpf_loop(MAX_DENTRY_DEPTH, file_walk_cb, &ctx, 0);
    return emit_walked_path(s, ctx.pos, ctx.done, ctx.failed, out, out_len);
}

#endif /* DOOR_FILE_WALK_H */
