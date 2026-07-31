/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1465-1668. */
#ifndef DOOR_FILE_PROC_H
#define DOOR_FILE_PROC_H

/* ---------------------------------------------------------------------------
 * Signal control.
 *
 * The sender is judged the same way every other operation is — the login uid
 * picks the policy, the employee narrows the rules. What is new is the TARGET
 * axis: another task, described by its image, its employee and its uid.
 *
 * Neither image can be resolved here. bpf_d_path is rejected at this attach
 * point on RHEL 9, so both come out of pid_image, filled on exec where the
 * helper is allowed. An image that is not in the map reads as unknown, and a
 * rule that constrains that side cannot match — the same fail-to-not-match rule
 * the employee axis uses, and for the same reason: a process wdog never saw
 * exec is an ordinary state, not an attack.
 * ------------------------------------------------------------------------- */

/* The image of a process, or NULL when it is not known. start_clock rejects an
 * entry left behind by a process whose pid has since been reused. */
static __always_inline struct pid_image *task_image(struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    struct pid_image *img = bpf_map_lookup_elem(&pid_image, &tgid);

    if (!img) return 0;
    if (img->start_clock != BPF_CORE_READ(task, start_boottime) / NSEC_PER_CLOCK)
        return 0;
    return img;
}

struct proc_check_ctx {
    void *inner;
    const char *policy_id;
    const char *exec_path;      /* sender's image, or NULL */
    const char *target_path;    /* target's image, or NULL */
    __u32 exec_path_len;
    __u32 target_path_len;
    __u32 uid;
    __u32 employee_id;
    __u32 target_employee_id;
    __u32 target_uid;
    __u32 count;
    __u32 sig;                  /* OP_KILL: the signal number */
    __u8 op;                    /* OP_KILL or OP_PTRACE; what the event reports */
    __u8 op_bit;                /* the same, as the PROC_OP_*_BIT a rule matches on */
    __u8 ptrace_mode;           /* OP_PTRACE: masked to PTRACE_MODE_MASK */
    __u8 matched;
    __u8 warning;               /* see struct policy_check_ctx::warning */
    int result;
};

static long check_proc_rule_cb(__u32 i, void *data)
{
    struct proc_check_ctx *ctx = data;
    __u32 zero = 0, index;
    struct proc_policy_slot *slot;
    struct proc_rule *r;
    struct runtime_config *cfg;
    __u8 denied, status, warn;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;

    /* One array holds the rules for both operations, so the first thing to do
     * is skip the ones that do not cover this one. A rule may cover both, and
     * then it is read by both hooks at its one position in the list — which is
     * what lets a single rule protect a target from signals and debugging
     * alike, and what keeps first-match-wins meaningful for each operation
     * independently. */
    if (!(r->op_mask & ctx->op_bit)) return 0;

    /* Cheapest first, exactly as the network rules order theirs: scalars
     * before the two pattern scans. */
    /* sig > 63 cannot be represented in the mask — Linux's SIGRTMAX is 64 and
     * bit 0 is already signal 0. Masking it down would alias SIGRTMAX onto the
     * kill(pid, 0) bit, so a rule that names any signal simply does not match
     * it; the loader rejects 64 in a rule for the same reason. */
    if (ctx->op == OP_KILL) {
        if (r->signals && (ctx->sig > 63 || !(r->signals & (1ULL << ctx->sig))))
            return 0;
    } else if (r->ptrace_mode && !(r->ptrace_mode & ctx->ptrace_mode)) {
        return 0;
    }
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
    if (r->target_employee_id != EMPLOYEE_ID_ANY &&
        r->target_employee_id != ctx->target_employee_id)
        return 0;
    if (r->has_target_uid && r->target_uid != ctx->target_uid) return 0;

    if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
        if (!ctx->exec_path) return 0;
        if (!match_path_pattern(r->exec_path, r->exec_wild, r->exec_suffix_len,
                                ctx->exec_path, ctx->exec_path_len))
            return 0;
    }
    if (!pattern_is_empty(r->target_path, r->target_wild)) {
        if (!ctx->target_path) return 0;
        if (!match_path_pattern(r->target_path, r->target_wild,
                                r->target_suffix_len, ctx->target_path,
                                ctx->target_path_len))
            return 0;
    }

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&runtime_config_map, &zero);
    /* Per-rule, per-policy or host-wide; see check_rule_cb for why cfg == NULL
     * still enforces. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    status = r->deny ? (warn ? 'W' : 'F') : 'S';
    if (!r->no_event)
        emit_event(ctx->uid, ctx->op, status, ctx->target_path ? ctx->target_path : "",
                   ctx->exec_path, ctx->policy_id, 1,
                   ctx->op == OP_KILL ? (__u8)ctx->sig : ctx->ptrace_mode, 0, index);
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Split out of the SEC() program because BPF_PROG names its own parameter
 * `ctx`, which would shadow the check context — the same reason every other
 * hook in this file is a thin wrapper over a check_* helper. */
static __always_inline int check_proc_policy(struct task_struct *p, __u8 op,
                                             __u8 op_bit, __u32 sig,
                                             __u8 ptrace_mode)
{
    __u32 uid, zero = 0, count;
    struct task_struct *task;
    struct proc_policy_slot *meta;
    struct proc_check_ctx ctx;
    struct pid_image *self_img, *target_img;
    void *inner;

    if (task_is_exempt()) return 0;
    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&active_proc_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    self_img = task_image(task);
    target_img = task_image(p);
    ctx = (struct proc_check_ctx){
        .inner = inner,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        .exec_path = self_img ? self_img->exe_path : 0,
        .target_path = target_img ? target_img->exe_path : 0,
        .exec_path_len = self_img ? self_img->path_len : 0,
        .target_path_len = target_img ? target_img->path_len : 0,
        .uid = uid,
        .employee_id = current_employee_id(task, uid),
        .target_employee_id = target_employee_id(p),
        .target_uid = BPF_CORE_READ(p, cred, uid.val),
        .count = count,
        .sig = sig,
        .op = op,
        .op_bit = op_bit,
        .ptrace_mode = ptrace_mode,
    };
    bpf_loop(MAX_RULES, check_proc_rule_cb, &ctx, 0);
    return ctx.result;
}

SEC("lsm/task_kill")
long BPF_PROG(wax_check_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    return lsm_ret(check_proc_policy(p, OP_KILL, PROC_OP_KILL_BIT, (__u32)sig, 0));
}

/*
 * Debugging access. Worth controlling alongside signals rather than instead of
 * them: stopping someone from killing a process while leaving them able to
 * attach to it protects very little, since a debugger can read its memory and
 * drive it wherever it likes.
 *
 * This hook is not only ptrace(2). The kernel routes every "may I inspect that
 * task" question through it, so a READ-mode rule also governs /proc/<pid>/mem
 * and /proc/<pid>/environ, process_vm_readv() and kcmp(). That reach is the
 * point — reading another process's environ is how credentials leak — but it
 * does mean a broad deny here stops more than a debugger.
 *
 * Access to one's own thread group returns before the hook is reached, so
 * nothing here can stop a process from inspecting itself.
 *
 * PTRACE_TRACEME has its own hook and is deliberately not covered: it is a
 * process asking its OWN parent to trace it, so it cannot be turned into a way
 * to reach a task these rules protect.
 */
SEC("lsm/ptrace_access_check")
long BPF_PROG(wax_check_ptrace, struct task_struct *child, unsigned int mode)
{
    /* mode also carries FSCREDS/REALCREDS/NOAUDIT; only the two access bits
     * are matched, and a mode outside them matches only unconstrained rules. */
    return lsm_ret(check_proc_policy(child, OP_PTRACE, PROC_OP_PTRACE_BIT, 0,
                                     (__u8)(mode & PTRACE_MODE_MASK)));
}

#endif /* DOOR_FILE_PROC_H */
