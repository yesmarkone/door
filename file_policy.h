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
    /* ORIGIN_BIT of the caller's session, resolved once per check rather than
     * per rule — current_session_axes hands it back alongside the employee id
     * that selected this policy. Exactly one bit is set, always: an
     * unclassifiable session carries ORIGIN_BIT(ORIGIN_UNKNOWN) rather than
     * zero, so the test in check_rule_cb needs no special case for it. */
    __u8 origin_bit;
    /* The deciding policy's observe-only flag; see struct policy_meta. Read
     * once from the meta slot the caller already resolved, so unlike the
     * runtime config it cannot be missing at decision time. */
    __u8 warning;
    /* Drop the 'S' for this one check; set from the OP_QUIET_S flag the caller
     * OR'd into op. Only wax_check_readdir sets it, and only for the second and
     * later getdents of one enumeration. Deliberately NOT a general mute: 'F'
     * and 'W' are unaffected, and the verdict is not touched at all. */
    __u8 quiet_s;
    int result;
};

/*
 * Keep rule traversal inside bpf_loop rather than a C-bounded loop.  Larger
 * policy limits would otherwise be unrolled by clang and exceed the verifier's
 * instruction limit before the program can load.
 *
 * `can_exec` is why this is a body plus two wrappers instead of one callback.
 * A bpf_loop callback is a real function with its own frame, so ctx->op is a
 * runtime value inside it and `ctx->op == OP_EXEC` can never fold — which means
 * the queue_exec_event() call below, and the bpf_d_path() inside it, are part of
 * every program that runs this loop. In lsm/file_permission that is fatal:
 * bpf_d_path does not load there at all (see walk_file_path in file_walk.h), and
 * the program is rejected for a call it can never reach. The wrappers give that
 * one caller a copy with the branch compiled out. OP_EXEC cannot arrive on the
 * walk form anyway — bprm_check_security is a sleepable hook and uses check().
 */
static __always_inline long check_rule_body(__u32 i, void *data, __u8 can_exec)
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
    /* No employee test here. The caller's person is half the key this policy was
     * found under, so by the time the loop runs it has already matched; see
     * struct policy_key. The compare that used to sit on this line was paid once
     * per rule per check, and getting it out of the loop is what bought the
     * budget for the extra lookup that key costs.
     *
     * The only user axis left in the loop is the origin below: one AND against a
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
    if ((status != 'S' || !ctx->quiet_s) &&
        rule_emits(r->permission & ctx->perm_mask, r->no_event_s,
                   r->no_event_fw, status)) {
        if (can_exec && ctx->op == OP_EXEC && !denied)
            queue_exec_event(ctx->uid, status, ctx->path, ctx->policy_id, index);
        else
            emit_event(ctx->uid, ctx->op, status, ctx->path, ctx->executable_path,
                       ctx->policy_id, ctx->op != OP_EXEC, 0, 0, index);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;
}

static long check_rule_cb(__u32 i, void *data)
{
    return check_rule_body(i, data, 1);
}

/* The copy without the exec-event arm, for callers that cannot call
 * bpf_d_path. See check_rule_body. */
static long check_rule_cb_noexec(__u32 i, void *data)
{
    return check_rule_body(i, data, 0);
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
 * list(16) for reading the names out of a directory;
 * delete(8) for unlink, rmdir and the source side of a rename;
 * write(4)|delete(8) for the destination side of a rename; write(4) for every
 * other filesystem change (write, truncate, chmod, chown, settime, mkdir,
 * symlink, link, mknod). The first rule whose permission mask, exec_path
 * pattern (current process image) and path pattern all match decides the
 * outcome.
 *
 * The employee is the second user axis, and it is spent before the first rule
 * is read: the login uid and the person PAM recorded together pick the policy.
 * That is what makes a shared account — one uid, many people — controllable per
 * person, and it means a policy's rules never have to name anyone. See
 * struct policy_key.
 *
 * `walk` selects how the current process image is resolved, and exists only
 * because hooks that are not in sleepable_lsm_hooks cannot call bpf_d_path — see
 * walk_file_path() in file_walk.h. It is always a literal at the call site and
 * this function is __always_inline, so each caller keeps one arm and the other
 * disappears; that is load-bearing, not an optimisation. A readdir program that
 * kept the bpf_d_path arm would not verify, and every other program would pay a
 * 48-iteration bpf_loop per check if it kept the walk arm. Do not turn `walk`
 * into a runtime value.
 *
 * `op` must be a literal at the call site for the same reason, and that is a
 * sharper constraint than it looks: queue_exec_event() also calls bpf_d_path,
 * so unless `op == OP_EXEC` folds to false the walk-form callers drag that call
 * into their program and fail to load. This is why the "quiet" flag below is its
 * own argument rather than a spare bit OR'd into op — riding in the op byte
 * would make op a runtime value and take the folding with it.
 *
 * `quiet_s` drops the 'S' for this one check. Only wax_check_readdir sets it,
 * for the second and later getdents of one enumeration; it is the one argument
 * here that is legitimately a runtime value, because it feeds nothing but a
 * context field. It never touches the verdict, and never suppresses 'F' or 'W'. */
static __always_inline int check_policy_impl(const char *path, __u32 path_len,
                                             __u8 op, __u8 walk, __u8 quiet_s)
{
    __u32 uid, zero = 0, count, exec_path_len = 0, employee_id;
    __u8 origin_bit;
    /* Assigned field by field below rather than left to a partial initializer:
     * this is a hash key, compared as eight raw bytes, so every byte of it has
     * to be one we put there. */
    struct policy_key key;
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
    /* FALLBACK_UID is AUDIT_UID_UNSET; see door/file_const.h. A task reading it
     * has no login uid, is therefore exempt, and every caller has already
     * returned — but if that ever stopped being true, the lookup below would
     * hand it the fallback policy instead of waving it through. Two instructions
     * to make the invariant local rather than a property of eleven call sites. */
    if (wax_fallback_on && uid == FALLBACK_UID) return 0;
    /* Both user axes come out of one session record, and the employee half is
     * needed HERE — it is half the key. That is why this sits ahead of the
     * lookup rather than just ahead of the rule loop where it used to be; the
     * origin half is carried down to the loop unchanged.
     *
     * ⚠ THIS LINE IS THE EXPENSIVE PART OF THE POLICY-KEY CHANGE, AND THE
     * SECOND LOOKUP BELOW IS NOT. Measured on RHEL 9 (5.14) with
     * LogLevelStats: wax_check_sendmsg, the program with the least verifier
     * budget, went from 316,945 to 557,242 instructions against the 1,000,000
     * ceiling. Deleting the unscoped lookup below and remeasuring gives
     * 556,936 — the lookup costs ~300. The rest is this call moving up.
     *
     * The reason is the shape this file warns about everywhere else: the two
     * maybe-null map lookups inside current_session_axes fork the verifier
     * state, and up here that fork sits AHEAD of bpf_d_path and the two glob
     * matchers instead of just ahead of the rule loop, so everything below is
     * explored on each path. barrier_var() on both outputs does not collapse
     * it (measured: no change).
     *
     * 44% headroom is what is left. Before adding anything to these programs,
     * measure. The retreat if it is ever crossed is --net-hooks dropping
     * sendmsg, the same lever --fallback-policy=file gives the fallback arm.
     *
     * The runtime cost of moving it up is that a uid with no policy at all now
     * pays the session lookups before finding that out. Only tasks that HAVE a
     * login uid reach this line — task_is_exempt() turned the others away — so
     * the population paying it is logged-in sessions, which is the population
     * that was paying it already whenever a policy existed. */
    current_session_axes(task, uid, &employee_id, &origin_bit);
    key.uid = uid;
    key.employee_id = employee_id;
    inner = bpf_map_lookup_elem(&wax_active_policy_by_uid, &key);
    /* No policy naming this person: the uid's unscoped policy takes them. This
     * is a REPLACEMENT and not a fallthrough — when the first lookup hits, the
     * unscoped policy is never consulted, so each policy carries its own
     * catch-all. See struct policy_key.
     *
     * Skipped when the session's employee is EMPLOYEE_ID_ANY, because then the
     * key above already was the unscoped one and this would repeat it. Hosts
     * where pam_wood.so is not yet everywhere are mostly that case. */
    if (!inner && employee_id != EMPLOYEE_ID_ANY) {
        key.employee_id = EMPLOYEE_ID_ANY;
        inner = bpf_map_lookup_elem(&wax_active_policy_by_uid, &key);
    }
    /* No policy of this user's own, and none anywhere for this uid: the host
     * fallback decides. A uid WITH a policy never reaches the fallback, not even
     * for the rule kinds its own policy leaves empty — wax_managed_uids is what
     * tells "unmanaged" apart from "managed, no rules of this kind", and
     * door/file_maps.h says why the difference matters. That map stays keyed by
     * uid alone: a uid whose only policies name individual employees is still
     * managed, and an unnamed session on it gets that uid's own default rather
     * than the host net meant for uids nobody enumerated.
     *
     * The fallback lives in the SAME outer map under a reserved key on purpose.
     * All three lookups then carry that map's one inner_map_meta, so the
     * verifier types the arms identically and merges them, and the rule loop
     * below — with its two nested glob matchers — is explored once. A separate
     * global array, the shape check_ingress uses, would give the arms different
     * map pointers and split that state in two; a split ahead of these same
     * matchers is what once put wax_check_sendmsg past the instruction ceiling.
     * It is also why the employee lookup above had to go in this map and not a
     * second one.
     *
     * The fallback is looked up before wax_managed_uids so that a host with none
     * installed pays one failed lookup here and stops.
     *
     * The three copies of this in net_policy.h, file_proc.h and file_cred.h are
     * deliberately identical down to the wording; only the map name differs. */
    if (wax_fallback_on && !inner) {
        struct policy_key fb = { .uid = FALLBACK_UID, .employee_id = EMPLOYEE_ID_ANY };
        void *fallback = bpf_map_lookup_elem(&wax_active_policy_by_uid, &fb);

        if (fallback && !bpf_map_lookup_elem(&wax_managed_uids, &uid))
            inner = fallback;
    }
    if (!inner) {
        /* No policy and no fallback. The empty policy id below is what tells
         * this record apart from one a fallback decided. */
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
            long n;

            /* Constant-folded; see the note on `walk` above. Both arms report
             * the same thing — a length that counts the NUL — so nothing below
             * has to know which one ran. */
            if (walk)
                n = walk_file_path(exe_file, executable_scratch->path,
                                   sizeof(executable_scratch->path));
            else
                n = bpf_d_path(&exe_file->f_path, executable_scratch->path,
                               sizeof(executable_scratch->path));

            if (n > 0) {
                exec_resolved = 1;
                exec_path_len = (__u32)n - 1;   /* n counts the NUL */
            }
        }
    }

    ctx = (struct policy_check_ctx){
        .inner = inner,
        .path = path,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        .warning = meta->meta.warning,
        /* Carried down from the session lookup that ran before the policy
         * lookup above, which is the same two hash lookups this check has
         * always paid — the employee half selected the policy and the origin
         * half is tested per rule. Policies with no origin-scoped rules still
         * pay for it but never consult the result. */
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
        .quiet_s = quiet_s,
    };
    /* Folded at the call site; see check_rule_body. */
    if (walk)
        bpf_loop(MAX_RULES, check_rule_cb_noexec, &ctx, 0);
    else
        bpf_loop(MAX_RULES, check_rule_cb, &ctx, 0);
    /* A configured policy still audits allowed executables that did not match
     * any rule.  Allowed matching rules have already queued their own event
     * in check_rule_cb. Nothing decided this one, so it carries no rule slot —
     * which is how such a record is told apart from an allow a rule granted. */
    if (op == OP_EXEC && !ctx.matched)
        queue_exec_event(uid, 'S', path, meta->meta.id, RULE_SLOT_NONE);
    return ctx.result;
}

/* The bpf_d_path form, for every hook that is in sleepable_lsm_hooks — which is
 * all of them but wax_check_readdir. */
static __always_inline int check_policy(const char *path, __u32 path_len, __u8 op)
{
    return check_policy_impl(path, path_len, op, 0, 0);
}

/* The dentry-and-mount-walk form, for hooks where bpf_d_path does not load. */
static __always_inline int check_policy_walk(const char *path, __u32 path_len,
                                             __u8 op, __u8 quiet_s)
{
    return check_policy_impl(path, path_len, op, 1, quiet_s);
}

#endif /* DOOR_FILE_POLICY_H */
