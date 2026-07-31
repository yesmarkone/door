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

/* Resolve this task's audit session to the employee id its rules are written
 * against: session -> name (what PAM recorded) -> id (what the loader interned).
 *
 * EMPLOYEE_ID_ANY comes back whenever that chain breaks, and every break is an
 * ordinary state rather than a failure: no PAM module installed, no name
 * configured for the login, or a name no rule mentions. Since a rule scoped to
 * an employee carries a non-zero id, such a session matches only the rules that
 * name nobody — deny rules included. Failing closed instead would deny every
 * unidentified session everything any name-scoped deny rule mentions, which is
 * most of the machine. "Deny whoever is not identified" is written as a
 * trailing catch-all deny rule naming no employee, which first-match-wins
 * reaches once the per-person rules above it have missed.
 *
 * Called once per check, before the rule loop. That placement is deliberate:
 * everything here branches on pointers, and doing any of it per rule is what
 * exhausts the verifier — see struct rule::employee_id. */
static __always_inline __u32 current_employee_id(struct task_struct *task,
                                                 __u32 login_uid)
{
    __u32 sid = BPF_CORE_READ(task, sessionid);
    struct session_identity *si;
    __u32 *id;

    if (sid == (__u32)-1) return EMPLOYEE_ID_ANY;
    si = bpf_map_lookup_elem(&wax_session_identity, &sid);
    if (!si) return EMPLOYEE_ID_ANY;
    /* Audit session ids are reused after a reboot, and a session killed hard
     * never runs close_session. A record whose login uid no longer matches is
     * one of those leftovers and must not lend its name to this task. */
    if (si->login_uid != login_uid) return EMPLOYEE_ID_ANY;
    /* The name is looked up in place: employee_name_key is exactly the leading
     * field of the record, so no copy to a key buffer is needed. */
    id = bpf_map_lookup_elem(&wax_employee_ids, si->employee_name);
    if (!id) return EMPLOYEE_ID_ANY;
    return *id;
}

/* The same resolution for a task that is not the current one — the target of a
 * signal. Kept separate rather than parameterising current_employee_id because
 * the login uid has to come from the task itself here, not from the policy
 * lookup that already resolved it for the caller. */
static __always_inline __u32 target_employee_id(struct task_struct *task)
{
    return current_employee_id(task, BPF_CORE_READ(task, loginuid.val));
}

#endif /* DOOR_FILE_MATCH_H */
