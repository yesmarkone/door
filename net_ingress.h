/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:1174-1301, before the split. */
#ifndef DOOR_NET_INGRESS_H
#define DOOR_NET_INGRESS_H

/*
 * ===========================================================================
 * Ingress evaluation
 * ===========================================================================
 */
struct ingress_ctx {
    __u8 src[16];
    __u8 local[16];
    __u32 count;
    /* The matching rule's slot, carried for the same reason status and emit
     * are: emit_ingress_event runs after bpf_loop. It reads this off the ctx it
     * already takes, so nothing about that function's signature changes. */
    __u32 rule_slot;
    __u16 sport;
    __u16 lport;
    __u8 family;
    __u8 matched;
    __u8 status;
    __u8 emit;
    /* The ingress policy's observe-only flag; see struct ingress_meta. Filled
     * from the meta slot check_ingress_policy reads before the loop. */
    __u8 warning;
    int result;
};

/* Same cheapest-first ordering and first-match-wins semantics as the egress
 * rules, over a much smaller rule: no patterns to scan, so the whole callback
 * is a handful of compares plus at most two prefix matches. */
static long check_ingress_rule_cb(__u32 i, void *data)
{
    struct ingress_ctx *ctx = data;
    __u32 zero = 0, index;
    struct ingress_slot *slot;
    struct ingress_rule *r;
    struct net_runtime_config *cfg;
    __u8 denied, warn;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(&wax_ingress_policy, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;
    if (r->family && r->family != ctx->family) return 0;
    /* Only TCP reaches this hook, so a rule naming another protocol cannot
     * match; the field exists so UDP support would not change the ABI. */
    if (r->protocol && r->protocol != IPPROTO_TCP) return 0;
    if (r->port_min != 0 || r->port_max != 0xffff) {
        if (ctx->lport < r->port_min || ctx->lport > r->port_max) return 0;
    }
    if (!match_addr_prefix(r->src_addr, r->src_prefix_len, ctx->src)) return 0;
    if (!match_addr_prefix(r->local_addr, r->local_prefix_len, ctx->local)) return 0;

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&wax_net_runtime_config_map, &zero);
    /* Warn because this rule is observe-only, or this policy is, or the whole
     * host is. cfg == NULL still enforces; see file.c's check_rule_cb. */
    warn = r->warn || ctx->warning || (cfg && cfg->mode == MODE_WARN);
    denied = r->deny && !warn;
    /* Both survive bpf_loop together, and must; see check_net_rule_cb.
     *
     * The one rule kind with no operation axis, so its byte stays the two
     * status bits and is expanded here into the one-bit masks the shared helper
     * takes: the single implicit operation is bit 0, NO_EVENT_SUCCESS is
     * already that bit, and NO_EVENT_DENY shifts down onto it. */
    ctx->status = r->deny ? (warn ? 'W' : 'F') : 'S';
    ctx->emit = rule_emits(1, r->no_event & NO_EVENT_SUCCESS,
                           (r->no_event & NO_EVENT_DENY) >> 1, ctx->status);
    ctx->rule_slot = index;
    /* Any non-zero return makes tcp_conn_request() drop the SYN. The client
     * sees a timeout rather than a refusal — there is no way to answer from
     * here, and staying silent is the conventional behaviour for a filtered
     * port anyway. A warned rule — whether by its own warn flag, its policy's
     * warning, or the global mode — therefore lets the connection complete and
     * reports 'W', instead of the client seeing a timeout. */
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Emit an ingress record. Deliberately not emit_net_event(): that one reads
 * current's cgroup, tty and argv, none of which mean anything in softirq. */
static __always_inline void emit_ingress_event(const struct ingress_ctx *ctx, __u8 status,
                                               const char *policy_id)
{
    struct net_event *e = bpf_ringbuf_reserve(&wax_net_events, sizeof(*e), 0);

    if (!e) return;
    zero_net_event(e);
    e->operation = OP_NET_INGRESS;
    e->status = status;
    e->rule_slot = ctx->rule_slot;
    e->create_timestamp_ns = bpf_ktime_get_ns();
    e->family = ctx->family;
    e->protocol = IPPROTO_TCP;
    e->sock_type = SOCK_STREAM;
    e->addr_valid = 1;
    e->no_task = 1;
    e->remote_port = ctx->sport;
    e->local_port = ctx->lport;
    __builtin_memcpy(e->remote_addr, ctx->src, 16);
    __builtin_memcpy(e->local_addr, ctx->local, 16);
    if (policy_id)
        bpf_probe_read_kernel_str(e->policy_id, sizeof(e->policy_id), policy_id);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int check_ingress(struct ingress_ctx *ctx)
{
    __u32 zero = 0, gen = 0;
    struct ingress_slot *meta;
    struct net_runtime_config *cfg;
    struct ingress_seen_key seen = {};
    __u32 *prev;

    meta = bpf_map_lookup_elem(&wax_ingress_policy, &zero);
    if (!meta) return 0;
    ctx->count = meta->meta.rule_count;
    if (ctx->count > MAX_RULES) ctx->count = MAX_RULES;
    if (ctx->count == 0) return 0;
    ctx->warning = meta->meta.warning;

    bpf_loop(MAX_RULES, check_ingress_rule_cb, ctx, 0);
    if (!ctx->matched || !ctx->emit) return ctx->result;

    cfg = bpf_map_lookup_elem(&wax_net_runtime_config_map, &zero);
    gen = cfg ? cfg->generation : 0;
    __builtin_memcpy(seen.src, ctx->src, 16);
    seen.sport = ctx->sport;
    seen.lport = ctx->lport;
    prev = bpf_map_lookup_elem(&wax_ingress_seen, &seen);
    if (prev && *prev == gen) return ctx->result;  /* a SYN retransmit */
    bpf_map_update_elem(&wax_ingress_seen, &seen, &gen, BPF_ANY);
    emit_ingress_event(ctx, ctx->status, meta->meta.id);
    return ctx->result;
}

#endif /* DOOR_NET_INGRESS_H */
