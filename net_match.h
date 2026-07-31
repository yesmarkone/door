/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:464-610. */
#ifndef DOOR_NET_MATCH_H
#define DOOR_NET_MATCH_H

/*
 * ===========================================================================
 * Verifier-friendly glob matcher — verbatim from door.c:195-305.
 * ===========================================================================
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

static __always_inline int pattern_is_empty(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '\0' && !(wild[0] & 1);
}

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
        if (path_len >= PATH_LEN) return 0;
        if (suffix_len > path_len) return 0;
        ctx.start = path_len - suffix_len;
        bpf_loop(PATH_LEN, match_suffix_cb, &ctx, 0);
        return ctx.matched;
    }
    bpf_loop(PATH_LEN, match_path_cb, &ctx, 0);
    return ctx.matched;
}

/*
 * ===========================================================================
 * Address matching — the only matcher that is new here.
 * ===========================================================================
 */

/* Compare the top prefix_len bits of two normalized 16-byte addresses. No
 * loops over rule data beyond the fixed 16 bytes, so this stays cheap enough to
 * sit in front of the pattern matchers in the per-rule ordering. */
static __always_inline int match_addr_prefix(const __u8 *rule, __u8 prefix_len,
                                             const __u8 *addr)
{
    __u32 bits, i;

    if (prefix_len == NET_ANY_PREFIX) return 1;
    if (prefix_len > 128) return 0;
    bits = prefix_len;

    /* Per-byte masks rather than a "full bytes then remainder" split: every
     * index stays a compile-time constant, so this unrolls cleanly and the
     * verifier never has to bound a variable offset into the rule. */
#pragma unroll
    for (i = 0; i < 16; i++) {
        __u32 have = bits > i * 8 ? bits - i * 8 : 0;
        __u8 mask;

        if (have >= 8) mask = 0xff;
        else if (have == 0) mask = 0;
        else mask = (__u8)(0xff << (8 - have));
        if ((rule[i] ^ addr[i]) & mask) return 0;
    }
    return 1;
}

/* Copied from door.c: session -> name -> interned id, resolved once per check.
 * See there for why every break in that chain yields EMPLOYEE_ID_ANY rather
 * than failing closed, and why none of this may happen per rule. */
static __always_inline __u32 current_employee_id(struct task_struct *task,
                                                 __u32 login_uid)
{
    __u32 sid = BPF_CORE_READ(task, sessionid);
    struct session_identity *si;
    __u32 *id;

    if (sid == (__u32)-1) return EMPLOYEE_ID_ANY;
    si = bpf_map_lookup_elem(&wax_session_identity, &sid);
    if (!si) return EMPLOYEE_ID_ANY;
    if (si->login_uid != login_uid) return EMPLOYEE_ID_ANY;
    id = bpf_map_lookup_elem(&wax_employee_ids, si->employee_name);
    if (!id) return EMPLOYEE_ID_ANY;
    return *id;
}

#endif /* DOOR_NET_MATCH_H */
