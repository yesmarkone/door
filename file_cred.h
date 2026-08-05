/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1669-1929, before the split. */
#ifndef DOOR_FILE_CRED_H
#define DOOR_FILE_CRED_H

/* -------------------------------------------------------------------------
 * Credential switching — setuid/setgid, and so su and sudo.
 *
 * The identity a task is switching TO is the thing an exec rule cannot see:
 * `sudo -u root` and `sudo -u oracle` are the same execve. That is what these
 * two hooks add, and the README leads with it.
 *
 * The identity it is switching FROM is the audit login uid, which already chose
 * the policy — see struct cred_rule for why the momentary real uid is not a
 * usable source axis. As with the process controls, bpf_d_path is rejected here
 * so the image comes from wax_pid_image.
 * ------------------------------------------------------------------------- */

/* The four id slots of a credential, in a fixed order shared by the new and old
 * sides so they can be compared positionally: real, effective, saved, fs. */
#define CRED_ID_SLOTS 4

/* Which slots this call actually moves, and what they move to. Positional —
 * changed[i] qualifies ids[i] — so no compaction and no variable-index write
 * into a stack array, which is the kind of thing the verifier makes expensive.
 * The same id landing in two slots is simply tested twice, which is harmless.
 *
 * SLOT-WISE, not "an id the task did not already hold anywhere". The difference
 * is the whole reason a rule against uid 0 works at all. su and sudo are
 * setuid-root binaries, so execve already put 0 in euid, suid and fsuid before
 * either of them runs a line of code; their later setuid(0) therefore acquires
 * nothing the task did not hold, and a rule matching only unheld ids would sit
 * there looking enforced while root was reached anyway (measured: `su root`
 * succeeded under a toUserID:0 deny, with no event). Comparing each slot to its
 * own previous value catches the real-uid move 1000 -> 0 that su performs.
 *
 * Nothing is lost by the change: an id absent from every old slot is by
 * definition absent from its own, so the old matches are a subset of these. The
 * no-op calls stay filtered, which is what keeps sudo's permission state
 * machine from flooding the ring buffer. */
struct cred_id_delta {
    __u32 ids[CRED_ID_SLOTS];   /* what each slot becomes */
    __u32 was[CRED_ID_SLOTS];   /* what it held before */
    __u8 changed[CRED_ID_SLOTS];
    __u8 any;
};

static __always_inline void cred_id_delta_of(struct cred_id_delta *out,
                                             const __u32 *new_ids,
                                             const __u32 *old_ids)
{
    out->any = 0;
#pragma unroll
    for (int i = 0; i < CRED_ID_SLOTS; i++) {
        __u8 changed = old_ids[i] != new_ids[i];

        out->ids[i] = new_ids[i];
        out->was[i] = old_ids[i];
        out->changed[i] = changed;
        if (changed) out->any = 1;
    }
}

/* Decide whether this call moves a slot the rule cares about, and describe that
 * one slot. When the rule names a destination it must be a slot that moved TO
 * it; when it names none, the first slot that moved at all — real, effective,
 * saved, fs, in that order.
 *
 * from and to come from the SAME slot on purpose. Reporting the old real uid
 * next to whichever id matched would render an effective-uid change of 1 -> 0
 * as "from_uid=0 to_uid=0", which reads as no change at all. */
static __always_inline __u8 delta_pick(const struct cred_id_delta *d,
                                       __u8 constrained, __u32 want,
                                       __u32 *from, __u32 *to)
{
    __u8 found = 0;

#pragma unroll
    for (int i = 0; i < CRED_ID_SLOTS; i++) {
        if (found || !d->changed[i]) continue;
        if (constrained && d->ids[i] != want) continue;
        found = 1;
        *from = d->was[i];
        *to = d->ids[i];
    }
    return found;
}

struct cred_check_ctx {
    void *inner;
    const char *policy_id;
    const char *exec_path;      /* the switching process's image, or NULL */
    const struct cred_id_delta *delta;
    __u32 exec_path_len;
    __u32 uid;                  /* login uid; the policy key and the event's */
    __u32 employee_id;
    __u32 count;
    __u8 op;                    /* OP_SETUID or OP_SETGID */
    __u8 op_bit;                /* the same, as the CRED_OP_*_BIT a rule matches */
    __u8 setid_flags;           /* LSM_SETID_*, for the event only */
    __u8 matched;
    __u8 warning;               /* see struct policy_check_ctx::warning */
    /* ORIGIN_BIT of the switching task's session; see struct
     * policy_check_ctx::origin_bit. Note WHOSE session this is on a login
     * descent: sshd and crond have already been given the arriving user's
     * session by pam_loginuid when they setuid down to them, so the origin here
     * is the one the arriving login will have. That is what makes an
     * origin-scoped credRule able to stop a login of that kind — and what makes
     * a careless one lock it out. */
    __u8 origin_bit;
    int result;
};

static long check_cred_rule_cb(__u32 i, void *data)
{
    struct cred_check_ctx *ctx = data;
    __u32 zero = 0, index, to_id;
    struct cred_policy_slot *slot;
    struct cred_rule *r;
    struct runtime_config *cfg;
    struct cred_event_ids ids;
    __u32 from_id = 0, want;
    __u8 denied, status, constrained, warn;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;

    /* One array holds the rules for both operations, so skip the ones that do
     * not cover this one — the same gate proc rules open with, and what keeps
     * first-match-wins meaningful for each operation independently. */
    if (!(r->op_mask & ctx->op_bit)) return 0;

    /* Cheapest first: the destination id is four scalar compares, the employee
     * one more, and only then the single pattern scan. */
    constrained = ctx->op == OP_SETUID ? r->has_to_uid : r->has_to_gid;
    want = ctx->op == OP_SETUID ? r->to_uid : r->to_gid;
    if (!delta_pick(ctx->delta, constrained, want, &from_id, &to_id)) return 0;
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
    if (r->origin_mask && !(r->origin_mask & ctx->origin_bit)) return 0;

    if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
        if (!ctx->exec_path) return 0;
        if (!match_path_pattern(r->exec_path, r->exec_wild, r->exec_suffix_len,
                                ctx->exec_path, ctx->exec_path_len))
            return 0;
    }

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&wax_runtime_config_map, &zero);
    /* Per-rule, per-policy or host-wide; see check_rule_cb for why cfg == NULL
     * still enforces. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    status = r->deny ? (warn ? 'W' : 'F') : 'S';
    /* One of CRED_OP_SETUID_BIT or CRED_OP_SETGID_BIT; see check_proc_rule_cb. */
    if (rule_emits(r->op_mask & ctx->op_bit, r->no_event_s, r->no_event_fw, status)) {
        ids.from_id = from_id;
        ids.to_id = to_id;
        ids.flags = ctx->setid_flags;
        /* No path: nothing is being acted on but the task's own identity. The
         * image that is doing it goes in executable_path, as everywhere else. */
        emit_event(ctx->uid, ctx->op, status, "", ctx->exec_path,
                   ctx->policy_id, 1, 0, &ids, index);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

static __always_inline int check_cred_policy(const struct cred *new_cred,
                                             const struct cred *old_cred,
                                             __u8 op, __u8 op_bit, int flags)
{
    __u32 uid, zero = 0, count, employee_id;
    __u8 origin_bit;
    __u32 new_ids[CRED_ID_SLOTS], old_ids[CRED_ID_SLOTS];
    struct cred_id_delta delta;
    struct task_struct *task;
    struct cred_policy_slot *meta;
    struct cred_check_ctx ctx;
    struct pid_image *self_img;
    void *inner;

    if (task_is_exempt()) return 0;

    /* op is a constant at each call site, so only one of these survives. */
    if (op == OP_SETUID) {
        new_ids[0] = BPF_CORE_READ(new_cred, uid.val);
        new_ids[1] = BPF_CORE_READ(new_cred, euid.val);
        new_ids[2] = BPF_CORE_READ(new_cred, suid.val);
        new_ids[3] = BPF_CORE_READ(new_cred, fsuid.val);
        old_ids[0] = BPF_CORE_READ(old_cred, uid.val);
        old_ids[1] = BPF_CORE_READ(old_cred, euid.val);
        old_ids[2] = BPF_CORE_READ(old_cred, suid.val);
        old_ids[3] = BPF_CORE_READ(old_cred, fsuid.val);
    } else {
        new_ids[0] = BPF_CORE_READ(new_cred, gid.val);
        new_ids[1] = BPF_CORE_READ(new_cred, egid.val);
        new_ids[2] = BPF_CORE_READ(new_cred, sgid.val);
        new_ids[3] = BPF_CORE_READ(new_cred, fsgid.val);
        old_ids[0] = BPF_CORE_READ(old_cred, gid.val);
        old_ids[1] = BPF_CORE_READ(old_cred, egid.val);
        old_ids[2] = BPF_CORE_READ(old_cred, sgid.val);
        old_ids[3] = BPF_CORE_READ(old_cred, fsgid.val);
    }
    cred_id_delta_of(&delta, new_ids, old_ids);
    /* Before the map lookup on purpose. The kernel calls these hooks on every
     * setuid-family syscall including the ones that change nothing, and sudo
     * alone makes a dozen of those per run; a call that moves no slot cannot be
     * what any rule here is about. */
    if (!delta.any) return 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&wax_active_cred_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    self_img = task_image(task);
    current_session_axes(task, uid, &employee_id, &origin_bit);
    ctx = (struct cred_check_ctx){
        .inner = inner,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        .exec_path = self_img ? self_img->exe_path : 0,
        .delta = &delta,
        .exec_path_len = self_img ? self_img->path_len : 0,
        .uid = uid,
        .employee_id = employee_id,
        .origin_bit = origin_bit,
        .count = count,
        .op = op,
        .op_bit = op_bit,
        .setid_flags = (__u8)flags,
    };
    bpf_loop(MAX_RULES, check_cred_rule_cb, &ctx, 0);
    return ctx.result;
}

/*
 * setuid(2) and its relatives — setreuid, setresuid, setfsuid. This is the hook
 * su and sudo trip when they switch user, and denying it makes them fail with
 * "cannot set user id" rather than silently proceed.
 *
 * Called before the new credentials are committed, so bpf_get_current_uid_gid()
 * inside emit_event still reports the old real uid.
 *
 * One caveat worth knowing: __sys_setfsuid discards the LSM error and returns
 * the old fsuid with no errno at all. A deny on an LSM_SETID_FS change is
 * therefore audited but not felt by the caller.
 */
SEC("lsm/task_fix_setuid")
long BPF_PROG(wax_check_setuid, struct cred *new, const struct cred *old, int flags)
{
    return lsm_ret(check_cred_policy(new, old, OP_SETUID, CRED_OP_SETUID_BIT, flags));
}

/*
 * setgid(2) and its relatives. Its own hook and its own selector because a
 * kernel that predates 5.13 has no task_fix_setgid to attach to.
 *
 * This covers the PRIMARY group only. security_task_fix_setgroups, which would
 * cover the supplementary list that initgroups() sets, does not exist on the
 * RHEL 9 kernels this runs on, so joining a privileged group that way is not
 * visible here. The README says so plainly.
 */
SEC("lsm/task_fix_setgid")
long BPF_PROG(wax_check_setgid, struct cred *new, const struct cred *old, int flags)
{
    return lsm_ret(check_cred_policy(new, old, OP_SETGID, CRED_OP_SETGID_BIT, flags));
}

#endif /* DOOR_FILE_CRED_H */
