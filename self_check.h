/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_CHECK_H
#define DOOR_SELF_CHECK_H

/*
 * COPIED FROM door/file_path.h:186-202 — KEEP IN SYNC.
 *
 * Strict LSM verifiers (RHEL 9.8, 5.14.0-687) require every hook to return a
 * value provably within [-4095, 0]. The hooks return `long` so clang sign-
 * extends into the full 64-bit R0, and barrier_var keeps clang from proving the
 * range at compile time and dropping the clamp.
 */
static __always_inline long lsm_ret(long r)
{
    barrier_var(r);
    if (r < -4095)
        r = -4095;
    barrier_var(r);
    if (r > 0)
        r = 0;
    barrier_var(r);
    return r;
}

/* The config, or NULL. Every caller treats NULL as "enforcing" — see
 * self_enforcing() and self_disarmed(). */
static __always_inline struct self_config *self_cfg(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&wax_self_config, &zero);
}

/* The cheapest possible first question, and every program asks it first: an
 * ARRAY lookup is a bounds check and an offset, where everything below is a
 * hash. A missing config is NOT disarmed — same direction as check_rule_cb's
 * `cfg && cfg->mode == MODE_WARN` (door/file_policy.h:91), and for the same
 * reason: a lookup that failed must not be the thing that turns a control off. */
static __always_inline int self_disarmed(void)
{
    struct self_config *cfg = self_cfg();

    return cfg && cfg->mode == SMODE_DISARMED;
}

static __always_inline int self_cfg_flag(__u16 flag)
{
    struct self_config *cfg = self_cfg();

    return cfg && (cfg->flags & flag);
}

/* Is the caller one of ours?
 *
 * This is the only thing standing between the guard and denying wdog its own
 * work, so it is worth stating what it does NOT do: it is never called first.
 * Every caller establishes that the object being touched is protected before
 * asking who is touching it, because this is a hash lookup and the
 * overwhelming majority of calls never reach it. */
static __always_inline int self_trusted(void)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct self_task_val *t = bpf_map_lookup_elem(&wax_self_tasks, &tgid);
    struct task_struct *task;

    if (!t) return 0;
    /* 0 means the entry does not pin a start time, which is what PID 1 gets. */
    if (!t->start_clock) return 1;
    task = (struct task_struct *)bpf_get_current_task_btf();
    /* group_leader, and NOT the current task. start_boottime is a per-THREAD
     * field — it records when that thread was created — while the value
     * userspace stored came from /proc/<tgid>/stat, which reports the thread
     * group LEADER's. wdog is a Go program with a dozen threads created
     * milliseconds apart, so reading it off the current task compares the
     * calling thread's birth against the process's and disagrees for every
     * thread but one.
     *
     * That is not a hypothetical: reading `task` here instead of
     * `task->group_leader` made wdog untrusted by its own guard, and the
     * symptom was the daemon refusing to load its own second BPF object. The
     * same shape appears in wax_pid_image (door/file_proc.h), where a
     * tgkill(2) aimed at a non-leader thread compares against that thread's
     * start time for the same reason. */
    return t->start_clock ==
           BPF_CORE_READ(task, group_leader, start_boottime) / NSEC_PER_CLOCK;
}

/* Is this dentry named exactly "loginuid"?
 *
 * Eight bytes, compared as a block. The only string comparison in this whole
 * object, and it is here rather than in a path because the alternative —
 * resolving the file to "/proc/<pid>/loginuid" and glob-matching it — would put
 * a bpf_d_path call and a pattern scan on the hook that fires for every open on
 * the system. The caller has already established that the superblock is procfs,
 * so a name match is conclusive. */
static __always_inline int self_name_is_loginuid(struct dentry *d)
{
    const unsigned char *name;
    char buf[8];

    if (BPF_CORE_READ(d, d_name.len) != 8) return 0;
    name = BPF_CORE_READ(d, d_name.name);
    if (!name) return 0;
    if (bpf_probe_read_kernel(buf, sizeof(buf), name) < 0) return 0;
    return __builtin_memcmp(buf, "loginuid", 8) == 0;
}

static __always_inline struct self_ino_val *self_ino(struct inode *inode)
{
    struct self_ino_key k = {};

    if (!inode) return 0;
    k.ino = BPF_CORE_READ(inode, i_ino);
    k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    return bpf_map_lookup_elem(&wax_self_inodes, &k);
}

/* The one decision site.
 *
 * Fail-closed throughout, and deliberately the opposite of what docs/hooks.md
 * §3 documents for the policy engine: there, a lookup that fails allows,
 * because a control that cannot resolve its subject should not invent one.
 * Here, a lookup that fails enforces, because the subject is already known —
 * the object was found in the protected set before this was reached — and the
 * only open question is whether to report or refuse.
 *
 * -EPERM (-1), not -EACCES (-13). The policy engine denies with -13 everywhere
 * (door/file_policy.h:107), so the different errno tells an operator which
 * layer refused from strace output alone, with no log correlation needed. */
static __always_inline long self_deny(__u8 op, __u8 kind, __u32 dev, __u64 ino,
                                      __u32 target, __u8 detail)
{
    struct self_config *cfg = self_cfg();
    __u8 enforcing = cfg ? (cfg->mode == SMODE_ARMED) : 1;

    emit_self_event(op, kind, enforcing ? 'F' : 'W', dev, ino, target, detail);
    return enforcing ? -1 /* EPERM */ : 0;
}

/* Does this operation modify anything?
 *
 * Every file-side caller passes a compile-time constant, so clang folds this
 * away entirely at each call site. That is what makes the read path free: the
 * `check(file, OP_READ)`-equivalent branch of wax_self_open does not merely
 * skip the walk at runtime, the walk is not in the program. Reading a protected
 * binary is not a way around anything, so nothing is lost by it. */
static __always_inline int self_op_writes(__u32 want)
{
    return (want & (SELF_NO_WRITE | SELF_NO_UNLINK | SELF_NO_MOUNT)) != 0;
}

struct self_tree_ctx {
    struct dentry *d;
    __u32 want;
    __u8 found;
    __u8 kind;
    __u8 done; /* reached the filesystem root: the miss is conclusive */
    __u8 _pad;
};

/* Walk toward the filesystem root looking for a directory the loader marked
 * SELF_IS_DIR. The shape mirrors dentry_walk_cb (door/file_path.h:104) so the
 * two read the same way, but this one compares inodes instead of building a
 * string — no scratch map, no PATH_LEN budget, no bpf_probe_read_kernel_str.
 *
 * MAX_SELF_DEPTH bounds the verifier, not the cost: bpf_loop charges per actual
 * iteration and this exits on the first match or at the root, so an ordinary
 * path costs three to eight probes. */
static long self_tree_cb(__u32 i, void *data)
{
    struct self_tree_ctx *ctx = data;
    struct dentry *d = ctx->d, *parent;
    struct self_ino_val *v;

    if (!d) return 1;
    v = self_ino(BPF_CORE_READ(d, d_inode));
    if (v && (v->flags & SELF_IS_DIR) && (v->flags & ctx->want)) {
        ctx->found = 1;
        ctx->kind = v->kind;
        return 1;
    }
    parent = BPF_CORE_READ(d, d_parent);
    if (!parent || parent == d) {
        ctx->done = 1;
        return 1;
    }
    ctx->d = parent;
    return 0;
}

/* 1 if some ancestor protects this dentry, 0 if provably not.
 *
 * Exhausting MAX_SELF_DEPTH without reaching the root is INCONCLUSIVE, and an
 * inconclusive answer denies. door/file_path.h:162-163 makes the opposite call
 * for the same situation — "Allow rather than mis-match on an incomplete walk"
 * — because there a wrong answer mis-applies a policy, while here a wrong
 * answer turns off the daemon's protection of itself. A path more than 48
 * components deep is pathological either way. */
static __always_inline int self_ancestor(struct dentry *dentry, __u32 want,
                                         __u8 *kind)
{
    struct self_tree_ctx ctx = { .d = dentry, .want = want };

    if (!dentry) return 0;
    if (!self_cfg_flag(SCFG_HAVE_TREE_GUARD)) return 0;
    bpf_loop(MAX_SELF_DEPTH, self_tree_cb, &ctx, 0);
    if (ctx.found) {
        *kind = ctx.kind;
        return 1;
    }
    if (!ctx.done) {
        *kind = SKIND_ANCESTOR;
        return 1; /* inconclusive: fail closed */
    }
    return 0;
}

/* The combined file-side check: this inode by identity, then any ancestor
 * directory by identity. Callers pass `want` as a constant. */
static __always_inline long self_guard(struct inode *inode,
                                       struct dentry *dentry, __u32 want,
                                       __u8 op, __u8 detail)
{
    struct self_ino_val *v;
    __u8 kind = SKIND_ANY;
    __u32 dev = 0;
    __u64 ino = 0;

    if (self_disarmed()) return 0;
    v = self_ino(inode);
    if (v && (v->flags & want)) {
        kind = v->kind;
    } else if (!self_op_writes(want) ||
               !self_ancestor(dentry, want, &kind)) {
        return 0;
    }
    if (self_trusted()) return 0;
    if (inode) {
        ino = BPF_CORE_READ(inode, i_ino);
        dev = BPF_CORE_READ(inode, i_sb, s_dev);
    }
    return self_deny(op, kind, dev, ino, 0, detail);
}

/* Convenience wrapper for the hooks that hand over a dentry and nothing else. */
static __always_inline long self_guard_dentry(struct dentry *dentry, __u32 want,
                                              __u8 op)
{
    return self_guard(BPF_CORE_READ(dentry, d_inode), dentry, want, op, 0);
}

/* Judge a directory in its own right, as the parent of something being created
 * or removed inside it.
 *
 * SELF_IS_DIR is a property of the ENTRY, never a member of `want` — an entry
 * has to carry both it and the wanted operation bit. Folding it into the mask
 * would make `v->flags & want` true for a directory marked IS_DIR alone and
 * deny every operation in it, which is the sort of bug a bitmask invites. */
static __always_inline long self_guard_parent(struct dentry *pd, __u32 want,
                                              __u8 op)
{
    struct self_ino_val *v;
    struct inode *inode;

    if (!pd) return 0;
    inode = BPF_CORE_READ(pd, d_inode);
    v = self_ino(inode);
    if (!v || !(v->flags & SELF_IS_DIR) || !(v->flags & want)) {
        __u8 kind = SKIND_ANY;

        if (!self_op_writes(want) || !self_ancestor(pd, want, &kind)) return 0;
        if (self_trusted()) return 0;
        return self_deny(op, kind, 0, 0, 0, 0);
    }
    if (self_trusted()) return 0;
    return self_deny(op, v->kind, BPF_CORE_READ(inode, i_sb, s_dev),
                     BPF_CORE_READ(inode, i_ino), 0, 0);
}

/* For the hooks whose target is a (parent path, dentry) pair: judge the dentry,
 * then the parent directory. The parent test is what covers creating a NEW name
 * inside a protected directory — a decoy pin beside the real one, or a
 * replacement agent.sock — where the target dentry is negative and carries no
 * inode at all for the first test to look at. */
static __always_inline long self_guard_dir_dentry(const struct path *dir,
                                                  struct dentry *dentry,
                                                  __u32 want, __u8 op)
{
    long r = self_guard_dentry(dentry, want, op);

    if (r) return r;
    return self_guard_parent(BPF_CORE_READ(dir, dentry), want, op);
}

#endif /* DOOR_SELF_CHECK_H */
