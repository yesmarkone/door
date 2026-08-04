/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:673-830. */
#ifndef DOOR_FILE_MATCH_H
#define DOOR_FILE_MATCH_H

/*
 * Verifier-friendly glob matcher. Pattern bytes are stored unescaped; the wild
 * bitmap marks which positions are wildcards: '?' matches one non-NUL byte and
 * '*' is supported as a terminal wildcard (for example, "/usr/bin/" plus '*').
 * A '*' or '?' byte without its wild bit set matches only the literal byte.
 * Keeping the character scan in bpf_loop's callback prevents it from
 * multiplying the states of the outer policy loop on older 5.14-based
 * verifiers.
 */
struct path_match_ctx {
    const char *rule;
    const __u8 *wild;
    const char *path;
    __u32 start; /* suffix match: path offset the comparison starts at */
    __u8 matched;
};

static long match_path_cb(__u32 i, void *data)
{
    struct path_match_ctx *ctx = data;
    char rc, pc;
    __u8 w;

    if (i >= PATH_LEN) return 1;
    barrier_var(i);
    rc = ctx->rule[i];
    pc = ctx->path[i];
    w = ctx->wild[i >> 3] & (1 << (i & 7));

    if (w && rc == '*') {
        ctx->matched = 1;
        return 1;
    }
    if (rc == '\0') {
        ctx->matched = pc == '\0';
        return 1;
    }
    if (w && rc == '?') return pc == '\0';
    return rc != pc;
}

/* Suffix matcher for patterns that lead with a wildcard '*'. The wildcard's
 * span is fixed rather than searched — the loader supplies the suffix length,
 * so the comparison simply starts at path_len - suffix_len and walks forward,
 * keeping this the same single scan as the prefix case. Pattern index i + 1
 * skips the leading '*'; ctx->start is bounded by the caller so every path
 * index stays inside PATH_LEN. */
static long match_suffix_cb(__u32 i, void *data)
{
    struct path_match_ctx *ctx = data;
    __u32 ri = i + 1, pi = ctx->start + i;
    char rc, pc;
    __u8 w;

    if (ri >= PATH_LEN) return 1;
    barrier_var(ri);
    rc = ctx->rule[ri];
    if (rc == '\0') {           /* the whole suffix compared equal */
        ctx->matched = 1;
        return 1;
    }
    if (pi >= PATH_LEN) return 1;
    barrier_var(pi);
    pc = ctx->path[pi];
    w = ctx->wild[ri >> 3] & (1 << (ri & 7));

    if (w && rc == '?') return pc == '\0';
    return rc != pc;
}

/* A leading NUL with its wild bit clear is the "always matches any path"
 * pattern. Patterns must be NUL-terminated within PATH_LEN by the loader; a
 * pattern that fills all PATH_LEN bytes without a NUL never sets matched below,
 * so it safely fails to match rather than reading past the buffer. */
static __always_inline int pattern_is_empty(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '\0' && !(wild[0] & 1);
}

/* A wildcard '*' in position 0 anchors the pattern to the path's tail. An
 * escaped literal '*' has its wild bit clear and is not a suffix pattern. */
static __always_inline int pattern_is_suffix(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '*' && (wild[0] & 1);
}

static __always_inline int match_path_pattern(const char *pattern, const __u8 *wild,
                                              __u8 suffix_len, const char *path,
                                              __u32 path_len)
{
    struct path_match_ctx ctx = {
        .rule = pattern,
        .wild = wild,
        .path = path,
    };

    if (pattern_is_empty(pattern, wild)) return 1;
    if (pattern_is_suffix(pattern, wild)) {
        /* A bare "*" carries no suffix and matches like the empty pattern. */
        if (suffix_len == 0) return 1;
        /* Paths that did not fit PATH_LEN were truncated, so their real tail
         * is not observable here and a suffix rule must not claim a match. */
        if (path_len >= PATH_LEN) return 0;
        if (suffix_len > path_len) return 0;
        ctx.start = path_len - suffix_len;
        bpf_loop(PATH_LEN, match_suffix_cb, &ctx, 0);
        return ctx.matched;
    }
    bpf_loop(PATH_LEN, match_path_cb, &ctx, 0);
    return ctx.matched;
}

/* Resolve this task's audit session to the two axes its rules are written
 * against: the employee id (session -> name, what PAM recorded -> id, what the
 * loader interned) and the origin bit (session -> where the login came from).
 *
 * Both come out of ONE record and therefore one map lookup, which is the reason
 * they are resolved together rather than by a function each. The employee
 * lookup was already here; origin rides along on it for free.
 *
 * EMPLOYEE_ID_ANY and ORIGIN_UNKNOWN come back whenever that chain breaks, and
 * every break is an ordinary state rather than a failure: no PAM module
 * installed in this stack, no name configured for the login, or a name no rule
 * mentions. Since a rule scoped to an employee carries a non-zero id and a rule
 * scoped to an origin carries a mask that does not include the unknown bit,
 * such a session matches only the rules that constrain neither — deny rules
 * included. Failing closed instead would deny every unclassifiable session
 * everything any scoped deny rule mentions, which is most of the machine.
 * "Deny whoever is not identified" and "deny whatever cannot be placed" are
 * written as trailing catch-all deny rules, which first-match-wins reaches once
 * the scoped rules above them have missed.
 *
 * That matters more for origin than it did for the employee, because origin is
 * the axis an operator rolls out gradually: until pam_wood.so is in EVERY
 * session stack, some perfectly ordinary sessions are unknown, and the failure
 * direction here is what keeps that half-finished state from denying them
 * everything.
 *
 * Called once per check, before the rule loop. That placement is deliberate:
 * everything here branches on pointers, and doing any of it per rule is what
 * exhausts the verifier — see struct rule::employee_id. */
static __always_inline void current_session_axes(struct task_struct *task,
                                                 __u32 login_uid,
                                                 __u32 *employee_id,
                                                 __u8 *origin_bit)
{
    __u32 sid = BPF_CORE_READ(task, sessionid);
    struct session_identity *si;
    __u32 *id;

    *employee_id = EMPLOYEE_ID_ANY;
    *origin_bit = ORIGIN_BIT(ORIGIN_UNKNOWN);
    if (sid == (__u32)-1) return;
    si = bpf_map_lookup_elem(&wax_session_identity, &sid);
    if (!si) return;
    /* Audit session ids are reused after a reboot, and a session killed hard
     * never runs close_session. A record whose login uid no longer matches is
     * one of those leftovers and must not lend its name — or its origin — to
     * this task. */
    if (si->login_uid != login_uid) return;
    /* Bounded before the shift, and not only to keep it defined: origin is
     * written by a separate build (pam/pam.c), so a module newer than this
     * object can name an origin this object has never heard of. Leaving such a
     * session on the unknown bit is the same fail-to-not-match the rest of this
     * function takes. */
    if (si->origin <= ORIGIN_MAX) *origin_bit = ORIGIN_BIT(si->origin);
    /* The name is looked up in place: employee_name_key is exactly the leading
     * field of the record, so no copy to a key buffer is needed. */
    id = bpf_map_lookup_elem(&wax_employee_ids, si->employee_name);
    if (id) *employee_id = *id;
}

/* The same resolution for a task that is not the current one — the target of a
 * signal. Kept separate rather than parameterising current_session_axes because
 * the login uid has to come from the task itself here, not from the policy
 * lookup that already resolved it for the caller. */
static __always_inline void target_session_axes(struct task_struct *task,
                                                __u32 *employee_id,
                                                __u8 *origin_bit)
{
    current_session_axes(task, BPF_CORE_READ(task, loginuid.val),
                         employee_id, origin_bit);
}

#endif /* DOOR_FILE_MATCH_H */
