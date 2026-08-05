/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1062-1267, before the split. */
#ifndef DOOR_FILE_POLICY_H
#define DOOR_FILE_POLICY_H

struct policy_check_ctx {
    void *inner;
    const char *path;
    const char *executable_path;
    const char *policy_id;
    /* The caller's interned employee id, EMPLOYEE_ID_ANY when unknown.
     * Resolved once per check rather than per rule; see current_session_axes. */
    __u32 employee_id;
    __u32 uid;
    __u32 count;
    /* strlen of the two paths, for suffix matching. A value >= PATH_LEN means
     * the path did not fit the buffer and was truncated. */
    __u32 path_len;
    __u32 exec_path_len;
    __u8 op;
    /* A mask, not a single bit — the rename destination demands
     * PERM_WRITE|PERM_DELETE. net.c's identically-placed field really is one
     * bit, which is why the names differ. */
    __u8 perm_mask;
    __u8 matched;
    __u8 exec_resolved; /* current process image was resolved via bpf_d_path */
    /* ORIGIN_BIT of the caller's session, from the same lookup and on the same
     * terms as employee_id above. Exactly one bit is set, always — an
     * unclassifiable session carries ORIGIN_BIT(ORIGIN_UNKNOWN) rather than
     * zero, so the test in check_rule_cb needs no special case for it. */
    __u8 origin_bit;
    /* The deciding policy's observe-only flag; see struct policy_meta. Read
     * once from the meta slot the caller already resolved, so unlike the
     * runtime config it cannot be missing at decision time. */
    __u8 warning;
    int result;
};

/*
 * Keep rule traversal inside bpf_loop rather than a C-bounded loop.  Larger
 * policy limits would otherwise be unrolled by clang and exceed the verifier's
 * instruction limit before the program can load.
 */
static long check_rule_cb(__u32 i, void *data)
{
    struct policy_check_ctx *ctx = data;
    __u32 zero = 0, index;
    struct policy_slot *slot;
    struct rule *r;
    struct runtime_config *cfg;
    __u8 denied, status, warn;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;
    /* An intersection: the rule governs this operation if it carries any of the
     * bits the operation demands. */
    if (!(r->permission & ctx->perm_mask)) return 0;
    /* Scalars only, on purpose: see struct rule::employee_id. An unidentified
     * caller has EMPLOYEE_ID_ANY, so a rule scoped to anyone cannot match it. */
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
    /* The third user axis, and the cheapest of the three: one AND against a
     * mask both sides already hold. A rule constraining no origin carries 0 and
     * skips out on the first test, which is what every rule written before this
     * axis existed does. */
    if (r->origin_mask && !(r->origin_mask & ctx->origin_bit)) return 0;
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
             * cannot shadow a later deny. The path test below still applies. */
            if (!r->deny) return 0;
        }
    }
    if (!match_path_pattern(r->path, r->path_wild, r->path_suffix_len, ctx->path,
                            ctx->path_len))
        return 0;

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&wax_runtime_config_map, &zero);
    /* Warn because this rule is observe-only, or this policy is, or the whole
     * host is — three scopes of one switch, OR'd. See struct policy_meta.
     *
     * Note what this does NOT change: cfg == NULL still enforces, so a failed
     * runtime_config lookup remains fail-closed for every rule that leaves both
     * flags clear. Neither flag opens a new lookup-failure path: ctx->warning
     * came from a meta slot check_policy already read successfully, and r->warn
     * from the rule slot looked up at the top of this callback. Only the runtime
     * config can be missing at decision time, and only it is guarded. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    status = r->deny ? (warn ? 'W' : 'F') : 'S';
    /* Both arms below carry the same status, so gating the pair is exactly the
     * per-status gate rule_emits() applies; see file_const.h. The first
     * argument is the same intersection that let this rule match, recomputed
     * rather than stashed on the context because it is one AND on registers
     * already live and ctx is read by every callback iteration. */
    if (rule_emits(r->permission & ctx->perm_mask, r->no_event_s,
                   r->no_event_fw, status)) {
        if (ctx->op == OP_EXEC && !denied)
            queue_exec_event(ctx->uid, status, ctx->path, ctx->policy_id, index);
        else
            emit_event(ctx->uid, ctx->op, status, ctx->path, ctx->executable_path,
                       ctx->policy_id, ctx->op != OP_EXEC, 0, 0, index);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;
}

static __always_inline int task_is_exempt(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, sessionid) == (__u32)-1;
}

/* Evaluate an already-resolved path against the caller's policy. Policies
 * are selected — and events attributed — by the audit login uid, which
 * pam_loginuid assigns at login and survives su/sudo, so a user stays under
 * their own policy after switching to root. The operation selects the
 * permission mask rules must intersect — see op_perm_mask(): exec(1); read(2);
 * delete(8) for unlink, rmdir and the source side of a rename;
 * write(4)|delete(8) for the destination side of a rename; write(4) for every
 * other filesystem change (write, truncate, chmod, chown, settime, mkdir,
 * symlink, link, mknod). The first rule whose permission mask, employee_id,
 * exec_path pattern (current process image) and path pattern all match decides
 * the outcome.
 *
 * The employee is the second user axis: the login uid picks the policy, the
 * employee picks which of its rules apply. That is what makes a shared account —
 * one uid, many people — controllable per person. */
static __always_inline int check_policy(const char *path, __u32 path_len, __u8 op)
{
    __u32 uid, zero = 0, count, exec_path_len = 0, employee_id;
    __u8 origin_bit;
    struct task_struct *task;
    struct policy_slot *meta;
    struct policy_check_ctx ctx;
    struct executable_path_scratch *executable_scratch;
    struct mm_struct *mm;
    struct file *exe_file;
    void *inner;
    const char *executable_path = 0;
    __u8 exec_resolved = 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&wax_active_policy_by_uid, &uid);
    if (!inner) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0, RULE_SLOT_NONE);
        return 0;
    }
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0, RULE_SLOT_NONE);
        return 0;
    }
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) {
        if (op == OP_EXEC)
            queue_exec_event(uid, 'S', path, meta->meta.id, RULE_SLOT_NONE);
        return 0;
    }
    /* Resolve the current process image for exec_path matching. For OP_EXEC
     * this is still the invoking image (e.g. the shell): bprm_check runs
     * before the new image is committed. */
    executable_scratch = bpf_map_lookup_elem(&wax_executable_path_scratch, &zero);
    if (executable_scratch) {
        executable_scratch->path[0] = '\0';
        executable_path = executable_scratch->path;
        /* Keep these as typed pointer dereferences. bpf_d_path requires a
         * trusted PTR_TO_BTF_ID; BPF_CORE_READ would turn exe_file into a
         * scalar from the verifier's perspective. */
        mm = task->mm;
        exe_file = mm ? mm->exe_file : 0;
        if (exe_file) {
            long n = bpf_d_path(&exe_file->f_path, executable_scratch->path,
                                sizeof(executable_scratch->path));

            if (n > 0) {
                exec_resolved = 1;
                exec_path_len = (__u32)n - 1;   /* n counts the NUL */
            }
        }
    }

    current_session_axes(task, uid, &employee_id, &origin_bit);
    ctx = (struct policy_check_ctx){
        .inner = inner,
        .path = path,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        /* Two hash lookups per check, next to the bpf_d_path above that costs
         * considerably more. Policies with no name-scoped or origin-scoped
         * rules still pay them, but never consult the result. Note that adding
         * the origin axis added no lookup: both axes come out of the one
         * session record the employee lookup was already fetching. */
        .employee_id = employee_id,
        .origin_bit = origin_bit,
        .uid = uid,
        .count = count,
        .path_len = path_len,
        .exec_path_len = exec_path_len,
        /* OP_RENAME_TO exists only to pick a different mask below. Normalize it
         * here, before anything can read ctx.op, so both sides of a rename are
         * reported with the one operation code userspace knows. */
        .op = op == OP_RENAME_TO ? OP_RENAME : op,
        .perm_mask = op_perm_mask(op),
        .exec_resolved = exec_resolved,
    };
    bpf_loop(MAX_RULES, check_rule_cb, &ctx, 0);
    /* A configured policy still audits allowed executables that did not match
     * any rule.  Allowed matching rules have already queued their own event
     * in check_rule_cb. Nothing decided this one, so it carries no rule slot —
     * which is how such a record is told apart from an allow a rule granted. */
    if (op == OP_EXEC && !ctx.matched)
        queue_exec_event(uid, 'S', path, meta->meta.id, RULE_SLOT_NONE);
    return ctx.result;
}

#endif /* DOOR_FILE_POLICY_H */
