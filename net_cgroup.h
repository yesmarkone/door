/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:775-873. */
#ifndef DOOR_NET_CGROUP_H
#define DOOR_NET_CGROUP_H

/*
 * ===========================================================================
 * Event emission — cgroup walk and zeroing copied from door.c:307-421.
 * ===========================================================================
 */
struct cgroup_walk_ctx {
    struct kernfs_node *kn;
    struct net_cgroup_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

/*
 * RHEL 9.8 (kernel 5.14.0-687) backported the upstream rename of
 * kernfs_node::parent to kernfs_node::__parent. The build-time vmlinux.h only
 * carries one of the two names, so read whichever the running kernel exposes.
 */
struct kernfs_node___parent_flavor {
    struct kernfs_node___parent_flavor *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kernfs_node_parent(struct kernfs_node *kn)
{
    struct kernfs_node___parent_flavor *k = (void *)kn;

    if (bpf_core_field_exists(k->__parent))
        return (struct kernfs_node *)BPF_CORE_READ(k, __parent);
    return BPF_CORE_READ(kn, parent);
}

static long cgroup_walk_cb(__u32 i, void *data)
{
    struct cgroup_walk_ctx *ctx = data;
    struct kernfs_node *kn = ctx->kn, *parent;
    const char *name;
    __u32 pos, sz;
    long len;

    if (!kn) {
        ctx->failed = 1;
        return 1;
    }
    parent = kernfs_node_parent(kn);
    if (!parent) {                              /* kernfs root */
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(kn, name);
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
    ctx->kn = parent;
    return 0;
}

static __always_inline void fill_cgroup(struct net_event *e, struct task_struct *task)
{
    __u32 zero = 0;
    struct kernfs_node *kn;
    struct net_cgroup_scratch *s;
    struct cgroup_walk_ctx ctx;

    e->cgroup_id = bpf_get_current_cgroup_id();
    kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn) return;
    s = bpf_map_lookup_elem(&wax_net_cgroup_scratch_map, &zero);
    if (!s) return;
    s->build[PATH_LEN] = '\0';
    ctx = (struct cgroup_walk_ctx){ .kn = kn, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_CGROUP_DEPTH, cgroup_walk_cb, &ctx, 0);
    /* Leave the field empty rather than truncated on an incomplete walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return;
    if (ctx.pos == PATH_LEN) {                  /* task is in the root cgroup */
        e->cgroup[0] = '/';
        e->cgroup[1] = '\0';
        return;
    }
    bpf_probe_read_kernel_str(e->cgroup, PATH_LEN, &s->build[ctx.pos]);
}

#endif /* DOOR_NET_CGROUP_H */
