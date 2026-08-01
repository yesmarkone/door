/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:955-1173. */
#ifndef DOOR_NET_POLICY_H
#define DOOR_NET_POLICY_H

/*
 * ===========================================================================
 * Policy evaluation
 * ===========================================================================
 */
struct net_check_ctx {
    void *inner;
    const struct net_target *t;
    const char *executable_path;
    const char *policy_id;
    /* The caller's interned employee id, EMPLOYEE_ID_ANY when unknown.
     * Resolved once per check rather than per rule. */
    __u32 employee_id;
    __u32 uid;
    __u32 count;
    __u32 exec_path_len;
    /* The matching rule's slot, for the same reason status and emit are here:
     * the emit happens after bpf_loop, so what the callback decided has to
     * survive it. door.c's file, proc and cred contexts carry no such field —
     * they emit from inside the callback and pass the slot as an argument. */
    __u32 rule_slot;
    __u8 op;
    __u8 perm_bit;
    __u8 matched;
    __u8 exec_resolved; /* current process image was resolved via bpf_d_path */
    __u8 status;
    __u8 emit;
    /* The deciding policy's observe-only flag; see struct net_policy_meta. Read
     * once from the meta slot the caller already resolved, so unlike the
     * runtime config it cannot be missing at decision time. */
    __u8 warning;
    int result;
};

/*
 * Keep rule traversal inside bpf_loop rather than a C-bounded loop. Larger
 * policy limits would otherwise be unrolled by clang and exceed the verifier's
 * instruction limit before the program can load.
 *
 * Constraints are tested cheapest-first: the permission bit and the three
 * one-byte selectors reject the overwhelming majority of rules before any
 * address comparison or pattern scan runs.
 */
static long check_net_rule_cb(__u32 i, void *data)
{
    struct net_check_ctx *ctx = data;
    const struct net_target *t = ctx->t;
    __u32 zero = 0, index;
    struct net_policy_slot *slot;
    struct net_rule *r;
    struct net_runtime_config *cfg;
    __u8 denied, warn;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;
    if (!(r->permission & ctx->perm_bit)) return 0;
    /* Scalars only, on purpose: see struct rule::employee_id in door.c. */
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
    if (r->family && r->family != t->family) return 0;
    if (r->sock_type && r->sock_type != t->sock_type) return 0;
    if (r->protocol && r->protocol != t->protocol) return 0;
    /* Port and address constraints only ever describe IP sockets, so a rule
     * that sets either cannot match a target without a resolved address. */
    if (r->port_min != 0 || r->port_max != 0xffff) {
        if (!t->has_addr) return 0;
        if (t->port < r->port_min || t->port > r->port_max) return 0;
    }
    if (r->prefix_len != NET_ANY_PREFIX) {
        if (!t->has_addr) return 0;
        if (!match_addr_prefix(r->addr, r->prefix_len, t->addr)) return 0;
    }
    if (!pattern_is_empty(r->path, r->path_wild)) {
        if (!t->path) return 0;
        if (!match_path_pattern(r->path, r->path_wild, r->path_suffix_len,
                                t->path, t->path_len))
            return 0;
    }
    if (ctx->executable_path) {
        if (ctx->exec_resolved) {
            if (!match_path_pattern(r->exec_path, r->exec_wild,
                                    r->exec_suffix_len, ctx->executable_path,
                                    ctx->exec_path_len))
                return 0;
        } else if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
            /* The process image could not be resolved and this rule is scoped
             * to a specific exec_path, so we cannot confirm the match. Fail
             * closed for deny rules (treat the exec_path as matching so the
             * deny still fires); skip permissive rules so an unverified allow
             * cannot shadow a later deny. */
            if (!r->deny) return 0;
        }
    }

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&wax_net_runtime_config_map, &zero);
    /* Warn because this rule is observe-only, or this policy is, or the whole
     * host is. cfg == NULL still enforces, so a failed runtime_config lookup
     * remains fail-closed for every rule that leaves both flags clear; see
     * door.c's check_rule_cb. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    /* Both survive bpf_loop together, and must: no_event is judged against the
     * status this rule decided, and the emit happens after the loop. */
    ctx->status = r->deny ? (warn ? 'W' : 'F') : 'S';
    ctx->emit = rule_emits(r->no_event, ctx->status);
    ctx->rule_slot = index;
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Copied from door.c:591-596. Tasks with no audit session (systemd-started
 * daemons, kernel threads) bypass every check, exactly as they do for the file
 * controls in door.c — the control axis is the logged-in user. */
static __always_inline int task_is_exempt(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, sessionid) == (__u32)-1;
}

/* Evaluate a resolved socket target against the caller's policy. Policies are
 * selected — and events attributed — by the audit login uid, which pam_loginuid
 * assigns at login and which survives su/sudo, so a user stays under their own
 * policy after switching to root. A rule's employee_name narrows it further to
 * one person on that account — the login uid picks the policy, the name picks
 * which of its rules apply. The first rule whose permission bit and every
 * constraint match decides the outcome. Unlike door.c there is no audit event
 * for the no-rule-matched case; only a matching rule emits. */
static __always_inline int check_net_policy(const struct net_target *t, __u8 op,
                                            __u8 perm_bit)
{
    __u32 uid, zero = 0, count, exec_path_len = 0;
    struct task_struct *task;
    struct net_policy_slot *meta;
    struct net_check_ctx ctx;
    struct net_path_scratch *exec_scratch;
    struct mm_struct *mm;
    struct file *exe_file;
    void *inner;
    const char *executable_path = 0;
    __u8 exec_resolved = 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&wax_active_net_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    exec_scratch = bpf_map_lookup_elem(&wax_net_exec_path_scratch, &zero);
    if (exec_scratch) {
        exec_scratch->path[0] = '\0';
        executable_path = exec_scratch->path;
        /* Keep these as typed pointer dereferences. bpf_d_path requires a
         * trusted PTR_TO_BTF_ID; BPF_CORE_READ would turn exe_file into a
         * scalar from the verifier's perspective. */
        mm = task->mm;
        exe_file = mm ? mm->exe_file : 0;
        if (exe_file) {
            long n = bpf_d_path(&exe_file->f_path, exec_scratch->path,
                                sizeof(exec_scratch->path));

            if (n > 0) {
                exec_resolved = 1;
                exec_path_len = (__u32)n - 1;   /* n counts the NUL */
            }
        }
    }

    ctx = (struct net_check_ctx){
        .inner = inner,
        .t = t,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        /* Two hash lookups per check, next to the bpf_d_path above that costs
         * considerably more. Policies with no name-scoped rules still pay them,
         * but never consult the result. */
        .employee_id = current_employee_id(task, uid),
        .uid = uid,
        .count = count,
        .exec_path_len = exec_path_len,
        /* Redundant while the sentinel is zero and the initializer zero-fills
         * the rest, but it says what an unmatched check reports rather than
         * leaving it to be inferred. */
        .rule_slot = RULE_SLOT_NONE,
        .op = op,
        .perm_bit = perm_bit,
        .exec_resolved = exec_resolved,
    };
    bpf_loop(MAX_RULES, check_net_rule_cb, &ctx, 0);
    if (ctx.matched && ctx.emit)
        emit_net_event(uid, op, ctx.status, t, executable_path, meta->meta.id,
                       ctx.rule_slot);
    return ctx.result;
}

/*
 * Strict LSM verifiers (e.g. RHEL 9.8, kernel 5.14.0-687) require every hook to
 * return a value provably within [-4095, 0]; see door.c:852-879 for the full
 * rationale behind the `long` return type and the clamp.
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

#endif /* DOOR_NET_POLICY_H */
