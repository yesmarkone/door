/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:955-1173, before the split. */
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
    /* The AF_UNIX destination path, and its length.
     *
     * It duplicates net_target::path on purpose, and the duplication is what
     * makes check_net_policy a global subprogram. A global subprogram receives
     * a struct argument as PTR_TO_MEM: the bytes are readable, but a POINTER
     * stored inside those bytes comes back a scalar, and dereferencing it is
     * rejected. t->path is exactly such a pointer. So check_net_policy looks
     * wax_net_addr_scratch up for itself — the same buffer the hook already
     * wrote the path into — and the callback reads it from here instead.
     *
     * NULL when the destination is not an AF_UNIX path, which is what the
     * pattern test below keys on, same as t->path did. */
    const char *upath;
    __u32 upath_len;
    const char *executable_path;
    const char *policy_id;
    __u32 uid;
    __u32 count;
    __u32 exec_path_len;
    /* The matching rule's slot, for the same reason status and emit are here:
     * the emit happens after bpf_loop, so what the callback decided has to
     * survive it. file.c's file, proc and cred contexts carry no such field —
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
    /* ORIGIN_BIT of the caller's session, from the same lookup as employee_id
     * above. See struct policy_check_ctx::origin_bit in door/file_policy.h. */
    __u8 origin_bit;
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
    /* No employee test: the caller's person is half the key this policy was
     * found under. See struct policy_key — getting this compare out of the loop
     * is what paid for the extra lookup that key costs, and this is the loop
     * that had the least budget to give. */
    if (r->origin_mask && !(r->origin_mask & ctx->origin_bit)) return 0;
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
        if (!ctx->upath) return 0;
        if (!match_path_pattern(r->path, r->path_wild, r->path_suffix_len,
                                ctx->upath, ctx->upath_len))
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
     * file.c's check_rule_cb. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    /* Both survive bpf_loop together, and must: the no_event masks are judged
     * against the status this rule decided, and the emit happens after the
     * loop. perm_bit really is one bit here — unlike file.c's perm_mask — so
     * the intersection is that bit or nothing, and it matched. */
    ctx->status = r->deny ? (warn ? 'W' : 'F') : 'S';
    ctx->emit = rule_emits(r->permission & ctx->perm_bit, r->no_event_s,
                           r->no_event_fw, ctx->status);
    ctx->rule_slot = index;
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Copied from door/file_policy.h. Tasks with no audit session (systemd-started
 * daemons, kernel threads) bypass every check, exactly as they do for the file
 * controls in file.c — the control axis is the logged-in user. */
static __always_inline int task_is_exempt(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, sessionid) == (__u32)-1;
}

/* Evaluate a resolved socket target against the caller's policy. Policies are
 * selected — and events attributed — by the audit login uid, which pam_loginuid
 * assigns at login and which survives su/sudo, so a user stays under their own
 * policy after switching to root. The employee PAM recorded on that session is
 * the other half of the selection — one shared account can carry a different
 * policy per person, and the rules themselves then name nobody. See
 * struct policy_key. The first rule whose permission bit and every constraint
 * match decides the outcome. Unlike file.c there is no audit event for the
 * no-rule-matched case; only a matching rule emits.
 *
 * ===========================================================================
 * THIS IS A GLOBAL SUBPROGRAM (__noinline), AND THAT IS THE POINT.
 * ===========================================================================
 *
 * A global subprogram is verified ONCE, on its own, and the verifier does not
 * descend into it at the call site — it checks the argument types and takes the
 * return value as an unknown scalar. Everything below therefore costs each
 * program that calls it one flat price instead of a copy of this function's
 * state explosion folded into that program's own branches.
 *
 * Measured on 6.12, this object, before -> after:
 *
 *   wax_check_sendmsg   594,943 -> 76,698 insns   (the ceiling is 1,000,000)
 *   wax_check_bind      295,126 -> 75,889
 *   wax_check_connect   294,906 -> 75,899
 *   wax_check_listen    249,510 -> 75,856
 *   wax_check_accept    249,510 -> 75,856
 *   wax_check_create     47,276 -> 75,690   (the one that gets worse)
 *   whole object load     10.6s -> 0.71s,  size 237KB -> 182KB
 *
 * wax_check_sendmsg is the reason. It names this function TWICE — once on the
 * verdict-cache miss path and once for destinations the cache cannot key — and
 * inlined that meant two copies of the rule loop and two of the glob matcher in
 * the program with the least budget in the system. Restructuring the C to a
 * single call site does NOT fix it (measured: 607,573, slightly worse than
 * before, because clang tail-duplicates the block around the cache store).
 * Not being inlined is what fixes it.
 *
 * wax_check_create pays 28k more because it is the one hook whose own work is
 * trivial; it now carries the whole function rather than the slice of it that
 * constant-folding left. 76k against a 1,000,000 ceiling is not a price worth
 * bargaining over.
 *
 * WHAT THE BOUNDARY COSTS, so nobody re-inlines this to get it back:
 *
 *  - `t` arrives as PTR_TO_MEM_OR_NULL. The NULL test below is not defensive
 *    coding, it is the contract: without it the verifier rejects the function
 *    with "R1 invalid mem access 'mem_or_null'". (__arg_nonnull would say the
 *    same thing more cheaply but is 6.9+, and this object still targets 5.14.)
 *  - Pointers INSIDE `t` come back as scalars and cannot be dereferenced. That
 *    is why net_check_ctx carries its own upath; see the comment there.
 *  - `op` and `perm_bit` are now runtime values rather than literals folded at
 *    the call site. Nothing here branches on them in a way that mattered.
 *  - The return value is an unknown scalar to the caller, so lsm_ret()'s clamp
 *    is now load-bearing on every hook rather than belt-and-braces. It was
 *    already on every hook.
 *
 * Global subprograms are upstream 5.6 and struct-pointer arguments 5.13, so
 * both predate 5.14. Reverting is one word — put `static __always_inline` back
 * — and everything else in this file stays as it is. */
__noinline int check_net_policy(const struct net_target *t, __u8 op,
                                __u8 perm_bit)
{
    __u32 uid, zero = 0, count, exec_path_len = 0, employee_id;
    __u8 origin_bit;
    struct policy_key key;  /* see door/file_policy.h */
    struct task_struct *task;
    struct net_policy_slot *meta;
    struct net_check_ctx ctx;
    struct net_path_scratch *exec_scratch, *addr_scratch;
    struct mm_struct *mm;
    struct file *exe_file;
    void *inner;
    const char *executable_path = 0;
    __u8 exec_resolved = 0;

    if (!t) return 0;   /* the PTR_TO_MEM_OR_NULL contract; see above */
    /* The buffer the calling hook wrote any AF_UNIX destination path into.
     * Re-resolved here rather than followed through t->path, which a global
     * subprogram may not dereference. */
    addr_scratch = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    /* The (uid, employee) lookup and the host fallback, in the shape
     * door/file_policy.h explains at length — the reserved-key guard, the
     * managed-uid gate, why an employee-scoped policy replaces the unscoped one,
     * and why all three lookups share this one outer map rather than getting an
     * array apiece. Kept identical to that copy on purpose; only the map name
     * differs. */
    if (wax_net_fallback_on && uid == FALLBACK_UID) return 0;
    current_session_axes(task, uid, &employee_id, &origin_bit);
    key.uid = uid;
    key.employee_id = employee_id;
    inner = bpf_map_lookup_elem(&wax_active_net_policy_by_uid, &key);
    if (!inner && employee_id != EMPLOYEE_ID_ANY) {
        key.employee_id = EMPLOYEE_ID_ANY;
        inner = bpf_map_lookup_elem(&wax_active_net_policy_by_uid, &key);
    }
    if (wax_net_fallback_on && !inner) {
        struct policy_key fb = { .uid = FALLBACK_UID, .employee_id = EMPLOYEE_ID_ANY };
        void *fallback = bpf_map_lookup_elem(&wax_active_net_policy_by_uid, &fb);

        if (fallback && !bpf_map_lookup_elem(&wax_net_managed_uids, &uid))
            inner = fallback;
    }
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
        /* t->path is only ever the address scratch buffer or NULL, so the flag
         * travels through the struct and the pointer is re-derived here. */
        .upath = (t->path && addr_scratch) ? addr_scratch->path : 0,
        .upath_len = t->path_len,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        /* Carried down from the session lookup that ran before the policy
         * lookup above — two hash lookups per check, next to the bpf_d_path
         * that costs considerably more. The employee half selected the policy;
         * this half is tested per rule, and policies with no origin-scoped
         * rules pay for it without consulting the result. */
        .origin_bit = origin_bit,
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
        emit_net_event(uid, op, ctx.status, t, ctx.upath, executable_path,
                       meta->meta.id, ctx.rule_slot);
    return ctx.result;
}

/*
 * Strict LSM verifiers (e.g. RHEL 9.8, kernel 5.14.0-687) require every hook to
 * return a value provably within [-4095, 0]; see door/file_path.h for the full
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
