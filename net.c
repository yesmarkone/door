// SPDX-License-Identifier: GPL-2.0 OR MIT
// Dual-licensed; the kernel-facing license string stays GPL-compatible
// ("Dual MIT/GPL") so gpl_only helpers such as bpf_d_path remain usable.
//
// Network access control: outbound (connect/sendto), inbound (accept) and
// listening (bind/listen) over TCP, UDP, ICMP/raw and unix-domain sockets.
//
// This is a SEPARATE BPF object from door/door.c, which stays untouched. The
// two cannot share maps, so this file owns its own policy maps, runtime config
// and ring buffer; wdog loads both objects and merges the two event streams.
//
// ---------------------------------------------------------------------------
// COPIED FROM door/door.c — KEEP IN SYNC. door.c is the source of truth for
// all of the following, and it is vendored from an external repository, so a
// change there (commit 9c264eb changed the pattern grammar once already) must
// be mirrored here by hand:
//
//   lsm_ret()                                       door.c:863-879
//   path_match_ctx, match_path_cb, match_suffix_cb  door.c:204-263
//   pattern_is_empty/_is_suffix/match_path_pattern  door.c:269-305
//   struct session_identity, struct employee_name_key, current_employee_id()
//   the session_identity and employee_ids maps (SHARED via their pins, not
//   merely duplicated — the declarations must stay byte-identical)
//   task_is_exempt()                                door.c:591-596
//   kernfs_node_parent(), cgroup_walk_cb()          door.c:319-381
//   fill_cgroup()   (retargeted at struct net_event)
//   zero_event()    (retargeted at struct net_event)
//   PATH_LEN / TTY_LEN / CMDLINE_LEN / POLICY_ID_LEN / MAX_RULES /
//   MAX_CGROUP_DEPTH / MODE_ENFORCE / MODE_WARN
// ---------------------------------------------------------------------------
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
#define POLICY_ID_LEN 40
#define EMPLOYEE_NAME_LEN 64
#define EMPLOYEE_ID_ANY 0
#define MAX_RULES 512
#define MAX_CGROUP_DEPTH 32
#define MODE_ENFORCE 0
#define MODE_WARN    1

/* Network operation codes. door.c owns 1..13 for file-class operations; both
 * objects publish into the same userspace event stream, so these must not
 * collide with it. */
#define OP_NET_CREATE  20
#define OP_NET_BIND    21
#define OP_NET_LISTEN  22
#define OP_NET_ACCEPT  23
#define OP_NET_CONNECT 24
#define OP_NET_SEND    25
#define OP_NET_INGRESS 26

/* Permission bits selecting which operations a network rule governs. This is a
 * namespace of its own; it is unrelated to door.c's execute/read/write bits.
 * "listening" is bind|listen (12): UDP and raw sockets never call listen(), and
 * splitting the two keeps a client pinning its source port with bind() out of
 * the way of a rule that only means to stop servers. */
#define NPERM_CONNECT 1  /* outbound: connect(), and sendto() destinations */
#define NPERM_ACCEPT  2  /* inbound:  accept() */
#define NPERM_BIND    4  /* local address claim: bind() */
#define NPERM_LISTEN  8  /* listen() */
#define NPERM_CREATE  16 /* socket() itself — the lever for raw/ICMP */

/* prefix_len sentinel meaning "this rule places no constraint on the address".
 * A real prefix is 0..128 over the 16-byte normalized address. */
#define NET_ANY_PREFIX 255

#ifndef AF_UNIX
#define AF_UNIX  1
#endif
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define UNIX_PATH_MAX 108
/* Byte offsets inside a sockaddr, used with bpf_probe_read_kernel so we never
 * depend on the caller's sockaddr being large enough for a whole struct read. */
#define SA_FAMILY_OFF 0
#define SIN_PORT_OFF  2
#define SIN_ADDR_OFF  4
#define SIN6_PORT_OFF 2
#define SIN6_ADDR_OFF 8
#define SUN_PATH_OFF  2

/* A rule matches when every constraint it sets is satisfied; unset constraints
 * (0 family/protocol/sock_type, NET_ANY_PREFIX, full port range, empty pattern)
 * match anything. Patterns and their wildcard bitmaps carry exactly the same
 * meaning and use exactly the same matcher as door.c's struct rule.
 *
 * addr is always the 16-byte normalized form: IPv4 is stored IPv4-mapped
 * (::ffff:a.b.c.d) with 96 added to prefix_len, so one matcher serves both
 * families. path is the AF_UNIX socket path pattern (abstract sockets are
 * spelled with a leading '@'); it is ignored for IP sockets. */
struct net_rule {
    char exec_path[PATH_LEN];
    char path[PATH_LEN];
    __u8 exec_wild[PATH_LEN / 8];
    __u8 path_wild[PATH_LEN / 8];
    /* The second user axis, alongside the login uid that selected the policy.
     * An interned id rather than the name itself — see struct rule in door.c,
     * where check_net_sendmsg below is the program that made that necessary.
     * EMPLOYEE_ID_ANY constrains nobody. */
    __u32 employee_id;
    __u8 addr[16];
    __u8 enabled;
    __u8 permission;    /* NPERM_* bitmask */
    __u8 deny;
    __u8 no_event;
    __u8 exec_suffix_len;
    __u8 path_suffix_len;
    __u8 family;        /* 0=any, AF_UNIX 1, AF_INET 2, AF_INET6 10 */
    __u8 protocol;      /* 0=any, IPPROTO_* */
    __u8 sock_type;     /* 0=any, SOCK_STREAM 1, SOCK_DGRAM 2, SOCK_RAW 3 */
    __u8 prefix_len;    /* 0..128, or NET_ANY_PREFIX */
    __u8 _pad[2];
    __u16 port_min;     /* host byte order, inclusive */
    __u16 port_max;
};

struct net_policy_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN]; /* NUL-terminated policy id */
};

/* Copied from door.c — the two objects must agree on these layouts byte for
 * byte, because they share the pinned maps holding them. See door.c for the
 * rationale on login_uid and on the zero-padding invariant. */
struct session_identity {
    char employee_name[EMPLOYEE_NAME_LEN];
    __u32 login_uid;
    __u32 _pad;
};

struct employee_name_key {
    char name[EMPLOYEE_NAME_LEN];
};

struct net_policy_slot {
    union {
        struct net_policy_meta meta;
        struct net_rule rule;
    };
};

/* generation is bumped by the loader on every policy or mode change; cache
 * entries stamped with an older generation are ignored, so replacing a policy
 * needs no cache flush. */
struct net_runtime_config {
    __u32 mode;
    __u32 generation;
};

/* Deliberately not door.c's struct event: keeping the layouts independent means
 * door.c (and its pinned 1428-byte layout test) never has to move. Network
 * fields sit in the header hole so there is no trailing padding. */
struct net_event {
    __u32 uid;                 /*    0 — audit login uid */
    __u32 real_uid;            /*    4 */
    __u64 create_timestamp_ns; /*    8 */
    __u64 cgroup_id;           /*   16 */
    __u32 audit_session_id;    /*   24 */
    __u8 status;               /*   28 — 'S' allow, 'F' deny, 'W' warn */
    __u8 operation;            /*   29 — OP_NET_* */
    __u8 family;               /*   30 */
    __u8 protocol;             /*   31 */
    __u8 sock_type;            /*   32 */
    /* Distinguishes "the address is 0.0.0.0" from "this operation resolved no
     * address at all" (socket creation, unix domain). Which of local_/remote_
     * carries it follows from the operation: bind/listen/accept are local,
     * connect/sendmsg are remote. */
    __u8 addr_valid;           /*   33 */
    /* Set on records produced in softirq (ingress), where there is no task to
     * attribute: pid, ppid, tty, cgroup and cmdline are left zero and must be
     * read as "not available" rather than as a process with pid 0. */
    __u8 no_task;              /*   34 */
    __u8 _pad;                 /*   35 */
    __u16 local_port;          /*   36 */
    __u16 remote_port;         /*   38 */
    __u8 local_addr[16];       /*   40 */
    __u8 remote_addr[16];      /*   56 */
    __u32 pid;                 /*   72 */
    __u32 ppid;                /*   76 */
    __u32 cmdline_len;         /*   80 */
    __u32 _pad2;               /*   84 */
    char path[PATH_LEN];       /*   88 — AF_UNIX socket path; empty for IP */
    char executable_path[PATH_LEN]; /* 344 */
    char cgroup[PATH_LEN];     /*  600 — cgroup v2 path, best-effort */
    char policy_id[POLICY_ID_LEN];  /* 856 */
    char tty[TTY_LEN];         /*  896 */
    char cmdline[CMDLINE_LEN]; /*  960 */
};                             /* 1472: a multiple of 8, no tail padding */

/* Per-socket verdict cache for the sendmsg data path, keyed on the socket
 * alone. The destination lives in the value and is re-checked on every hit,
 * because one unconnected socket can sendto() many peers.
 *
 * Keying on the bare struct sock pointer is only sound because
 * check_net_sk_free() removes the entry when the socket is destroyed: the
 * kernel reuses those allocations freely, so without that hook a new socket
 * could land on a freed one's address and inherit its verdict — including one
 * decided for a different process under an exec-scoped rule. The uid is
 * matched too, which covers a socket handed to another process over
 * SCM_RIGHTS.
 *
 * The audit session id is matched alongside the uid, and has to be: on a shared
 * account two people log in under the SAME uid but different employee names, so
 * a uid check alone would let one person's verdict decide the other's send.
 *
 * Only IP sockets are cached: an AF_UNIX destination is a path that does not
 * fit here, and hashing one risks a collision deciding an access. */
struct net_cache_key {
    __u64 sk;
};

struct net_cache_val {
    __u32 generation;
    __u32 uid;        /* login uid the verdict was decided for */
    __u32 session_id; /* audit session, so two people on one account differ */
    __u8 addr[16];    /* destination it applies to */
    __u16 port;
    __u8 verdict; /* 1 = denied */
    __u8 emitted; /* the event for this (socket, destination) already went out */
};

/* ---------------------------------------------------------------------------
 * Ingress: a host-wide policy, deliberately outside the login-uid policy space.
 *
 * An arriving SYN has no task behind it — the hook runs in softirq, on whatever
 * CPU the packet landed on — so there is no login uid to key on and no process
 * to attribute. Ingress therefore gets its own single global rule array rather
 * than the per-uid map-in-map the egress rules use.
 *
 * TCP only, on purpose. security_sock_rcv_skb() would be needed for UDP and
 * ICMP, and it sits on the receive path of *every* packet including established
 * TCP data — measured at 739k calls for a workload whose ingress decisions
 * numbered zero. inet_conn_request() fires once per connection attempt instead,
 * so this costs nothing once a connection is up.
 * ------------------------------------------------------------------------- */
struct ingress_rule {
    __u8 src_addr[16];      /* source prefix, v4-mapped */
    __u8 local_addr[16];    /* local (destination) prefix, v4-mapped */
    __u8 enabled;
    __u8 deny;
    __u8 no_event;
    __u8 family;            /* 0=any, AF_INET 2, AF_INET6 10 */
    __u8 protocol;          /* 0=any, IPPROTO_TCP 6; only TCP arrives here today */
    __u8 src_prefix_len;    /* 0..128, or NET_ANY_PREFIX */
    __u8 local_prefix_len;
    __u8 _pad;
    __u16 port_min;         /* local (listening) port, host byte order */
    __u16 port_max;
};

struct ingress_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN];
};

struct ingress_slot {
    union {
        struct ingress_meta meta;
        struct ingress_rule rule;
    };
};

/* Suppresses duplicate events from SYN retransmissions: one connection attempt
 * re-enters this hook every time the client retries, so a single blocked
 * connect() was measured emitting two records and a port scan would emit
 * thousands. Keyed on the connection's four-tuple minus the parts that do not
 * vary across a retransmit. */
struct ingress_seen_key {
    __u8 src[16];
    __u16 sport;
    __u16 lport;
};

struct net_path_scratch {
    char path[PATH_LEN];
};

/* Same 2x headroom rationale as door.c's dentry_walk_scratch: the cgroup walk
 * writes at a variable offset and the verifier bounds it by the worst cases
 * added together. */
struct net_cgroup_scratch {
    char build[PATH_LEN * 2];
    char name[PATH_LEN];
};

/* The userspace loader writes these two by byte offset (cmd/wdog/net.go) and
 * pins the sizes in net_test.go, so a silent layout change here would corrupt
 * policy and events rather than fail to build. */
_Static_assert(sizeof(struct net_rule) == 612, "struct net_rule must stay 612 bytes");
_Static_assert(sizeof(struct net_event) == 1472, "struct net_event must stay 1472 bytes");
_Static_assert(sizeof(struct net_event) % 8 == 0, "zero_net_event needs a multiple of 8");
_Static_assert(sizeof(struct ingress_rule) == 44, "struct ingress_rule must stay 44 bytes");
_Static_assert(sizeof(struct ingress_slot) == 44, "struct ingress_slot must stay 44 bytes");

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_policy_slot);
} net_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(net_policy_template));
} active_net_policy_by_uid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_runtime_config);
} net_runtime_config_map SEC(".maps");

/* Audit session id -> the employee PAM logged in on it. THE SAME MAP door.c
 * declares, not a copy: LIBBPF_PIN_BY_NAME means whichever object loads second
 * attaches to the one the first created, which is the only way these two
 * objects can share state. Every attribute below must therefore stay identical
 * to door.c's declaration, or the second load fails on a layout mismatch. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* audit session id */
    __type(value, struct session_identity);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} session_identity SEC(".maps");

/* Employee name -> the id rules carry. THE SAME MAP door.c declares, shared
 * through its pin; both objects must resolve a name to the same id. Every
 * attribute must stay identical to door.c's declaration. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct employee_name_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} employee_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} net_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct net_cache_key);
    __type(value, struct net_cache_val);
} net_verdict_cache SEC(".maps");

/* The ingress policy: one global array, not keyed by anything. Slot 0 is the
 * metadata, slots 1..rule_count the ordered rules — the same shape as an inner
 * policy map, minus the uid dimension it has no use for. Mode and generation
 * come from net_runtime_config_map, shared with the egress rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct ingress_slot);
} ingress_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct ingress_seen_key);
    __type(value, __u32); /* the generation the record was emitted under */
} ingress_seen SEC(".maps");

/* bpf_d_path output is kept off the BPF stack; the hooks call policy callbacks
 * and matchers, so a 256-byte local would blow the 512-byte combined limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_path_scratch);
} net_exec_path_scratch SEC(".maps");

/* Holds the extracted AF_UNIX socket path for the duration of one hook. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_path_scratch);
} net_addr_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_cgroup_scratch);
} net_cgroup_scratch_map SEC(".maps");

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
    si = bpf_map_lookup_elem(&session_identity, &sid);
    if (!si) return EMPLOYEE_ID_ANY;
    if (si->login_uid != login_uid) return EMPLOYEE_ID_ANY;
    id = bpf_map_lookup_elem(&employee_ids, si->employee_name);
    if (!id) return EMPLOYEE_ID_ANY;
    return *id;
}

/* Everything one hook learned about the socket it is deciding on. */
struct net_target {
    __u8 addr[16];      /* normalized peer (connect/sendmsg) or local address */
    __u64 sk;           /* struct sock *, for the verdict cache key */
    const char *path;   /* AF_UNIX socket path, or NULL */
    __u32 path_len;
    __u16 port;
    __u8 family;
    __u8 protocol;
    __u8 sock_type;
    __u8 has_addr;      /* an IP address/port was resolved */
    __u8 is_remote;     /* address describes the peer, not the local end */
};

static __always_inline int addrs_equal(const __u8 *a, const __u8 *b)
{
#pragma unroll
    for (int i = 0; i < 16; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

static __always_inline void set_v4_mapped(__u8 *a16, __be32 v4)
{
    __builtin_memset(a16, 0, 10);
    a16[10] = 0xff;
    a16[11] = 0xff;
    __builtin_memcpy(a16 + 12, &v4, 4);
}

/* Copy a unix socket path out of a kernel-resident sockaddr_un. Abstract
 * sockets (a leading NUL) are spelled '@name', matching how ss(8) prints them,
 * so policies can target them with a "@*" pattern. Returns the string length. */
static __always_inline __u32 read_unix_path(const void *sa, int addrlen, char *out)
{
    const char *sun_path = (const char *)sa + SUN_PATH_OFF;
    char first = 0;
    long len;

    out[0] = '\0';
    if (addrlen <= SUN_PATH_OFF) return 0; /* autobind: unnamed socket */
    if (bpf_probe_read_kernel(&first, 1, sun_path) < 0) return 0;
    if (first == '\0') {
        out[0] = '@';
        len = bpf_probe_read_kernel_str(&out[1], UNIX_PATH_MAX, sun_path + 1);
        if (len <= 0) {
            out[0] = '\0';
            return 0;
        }
        return (__u32)len; /* 1 for '@' + (len - 1) name bytes */
    }
    len = bpf_probe_read_kernel_str(out, UNIX_PATH_MAX, sun_path);
    if (len <= 0) {
        out[0] = '\0';
        return 0;
    }
    return (__u32)len - 1;
}

/* Decode the sockaddr a syscall handed in. bind/connect/sendmsg all receive it
 * already copied into kernel memory (move_addr_to_kernel runs before the LSM
 * hook), so probe_read_kernel is correct for every one of them. Fields are read
 * individually rather than as whole structs so a short addrlen still works. */
static __always_inline int read_sockaddr(const void *sa, int addrlen,
                                         struct net_target *t, char *pathbuf)
{
    __u16 fam = 0;

    if (!sa || addrlen < 2) return -1;
    if (bpf_probe_read_kernel(&fam, sizeof(fam), (const char *)sa + SA_FAMILY_OFF) < 0)
        return -1;

    if (fam == AF_INET) {
        __be16 port = 0;
        __be32 v4 = 0;

        if (addrlen < SIN_ADDR_OFF + 4) return -1;
        if (bpf_probe_read_kernel(&port, 2, (const char *)sa + SIN_PORT_OFF) < 0) return -1;
        if (bpf_probe_read_kernel(&v4, 4, (const char *)sa + SIN_ADDR_OFF) < 0) return -1;
        set_v4_mapped(t->addr, v4);
        t->port = bpf_ntohs(port);
        t->family = AF_INET;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_INET6) {
        __be16 port = 0;

        if (addrlen < SIN6_ADDR_OFF + 16) return -1;
        if (bpf_probe_read_kernel(&port, 2, (const char *)sa + SIN6_PORT_OFF) < 0) return -1;
        if (bpf_probe_read_kernel(t->addr, 16, (const char *)sa + SIN6_ADDR_OFF) < 0) return -1;
        t->port = bpf_ntohs(port);
        t->family = AF_INET6;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_UNIX) {
        t->family = AF_UNIX;
        t->path = pathbuf;
        t->path_len = read_unix_path(sa, addrlen, pathbuf);
        return 0;
    }
    /* Other families (netlink, packet, ...) still get family-level matching. */
    t->family = (__u8)fam;
    return 0;
}

/* Socket-level attributes that every hook wants, independent of any address. */
static __always_inline void read_sock_meta(struct socket *sock, struct net_target *t)
{
    struct sock *sk;

    if (!sock) return;
    t->sock_type = (__u8)BPF_CORE_READ(sock, type);
    sk = BPF_CORE_READ(sock, sk);
    if (!sk) return;
    t->sk = (__u64)(unsigned long)sk;
    t->protocol = (__u8)BPF_CORE_READ(sk, sk_protocol);
}

/* Resolve the socket's local address, for hooks that get no sockaddr argument
 * (listen, accept). skc_num is already host byte order. */
static __always_inline int read_sock_local(struct socket *sock, struct net_target *t,
                                           char *pathbuf)
{
    struct sock *sk;
    __u16 fam;

    read_sock_meta(sock, t);
    sk = BPF_CORE_READ(sock, sk);
    if (!sk) return -1;
    fam = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (fam == AF_INET) {
        set_v4_mapped(t->addr, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        t->port = BPF_CORE_READ(sk, __sk_common.skc_num);
        t->family = AF_INET;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_INET6) {
        BPF_CORE_READ_INTO(t->addr, sk, __sk_common.skc_v6_rcv_saddr);
        t->port = BPF_CORE_READ(sk, __sk_common.skc_num);
        t->family = AF_INET6;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_UNIX) {
        struct unix_sock *u = (struct unix_sock *)sk;
        struct unix_address *ua = BPF_CORE_READ(u, addr);

        t->family = AF_UNIX;
        if (ua) {
            int alen = BPF_CORE_READ(ua, len);

            t->path = pathbuf;
            t->path_len = read_unix_path(&ua->name[0], alen, pathbuf);
        }
        return 0;
    }
    t->family = (__u8)fam;
    return 0;
}

/*
 * ===========================================================================
 * Event emission — cgroup walk and zeroing copied from door.c:307-421.
 * ===========================================================================
 */
struct cgroup_walk_ctx {
    struct kernfs_node *kn;
    struct net_cgroup_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

/*
 * RHEL 9.8 (kernel 5.14.0-687) backported the upstream rename of
 * kernfs_node::parent to kernfs_node::__parent. The build-time vmlinux.h only
 * carries one of the two names, so read whichever the running kernel exposes.
 */
struct kernfs_node___parent_flavor {
    struct kernfs_node___parent_flavor *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kernfs_node_parent(struct kernfs_node *kn)
{
    struct kernfs_node___parent_flavor *k = (void *)kn;

    if (bpf_core_field_exists(k->__parent))
        return (struct kernfs_node *)BPF_CORE_READ(k, __parent);
    return BPF_CORE_READ(kn, parent);
}

static long cgroup_walk_cb(__u32 i, void *data)
{
    struct cgroup_walk_ctx *ctx = data;
    struct kernfs_node *kn = ctx->kn, *parent;
    const char *name;
    __u32 pos, sz;
    long len;

    if (!kn) {
        ctx->failed = 1;
        return 1;
    }
    parent = kernfs_node_parent(kn);
    if (!parent) {                              /* kernfs root */
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(kn, name);
    len = bpf_probe_read_kernel_str(ctx->s->name, PATH_LEN, name);
    if (len <= 1) {
        ctx->failed = 1;
        return 1;
    }
    sz = (__u32)len - 1;                        /* component bytes, no NUL */
    if (sz >= PATH_LEN || ctx->pos < sz + 1) {  /* out of path budget */
        ctx->failed = 1;
        return 1;
    }
    pos = ctx->pos - (sz + 1);
    if (pos >= PATH_LEN) {                      /* bound for the verifier */
        ctx->failed = 1;
        return 1;
    }
    ctx->s->build[pos] = '/';
    if (bpf_probe_read_kernel(&ctx->s->build[pos + 1], sz, ctx->s->name) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->pos = pos;
    ctx->kn = parent;
    return 0;
}

static __always_inline void fill_cgroup(struct net_event *e, struct task_struct *task)
{
    __u32 zero = 0;
    struct kernfs_node *kn;
    struct net_cgroup_scratch *s;
    struct cgroup_walk_ctx ctx;

    e->cgroup_id = bpf_get_current_cgroup_id();
    kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn) return;
    s = bpf_map_lookup_elem(&net_cgroup_scratch_map, &zero);
    if (!s) return;
    s->build[PATH_LEN] = '\0';
    ctx = (struct cgroup_walk_ctx){ .kn = kn, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_CGROUP_DEPTH, cgroup_walk_cb, &ctx, 0);
    /* Leave the field empty rather than truncated on an incomplete walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return;
    if (ctx.pos == PATH_LEN) {                  /* task is in the root cgroup */
        e->cgroup[0] = '/';
        e->cgroup[1] = '\0';
        return;
    }
    bpf_probe_read_kernel_str(e->cgroup, PATH_LEN, &s->build[ctx.pos]);
}

/* bpf_ringbuf_reserve hands back uninitialized memory, and clang refuses to
 * inline a memset this large for the BPF target, so clear the record with an
 * unrolled word loop. sizeof(struct net_event) is a multiple of 8 and
 * ring-buffer memory is 8-byte aligned. */
static __always_inline void zero_net_event(struct net_event *e)
{
    volatile __u64 *p = (volatile __u64 *)e;

#pragma unroll
    for (int i = 0; i < sizeof(*e) / 8; i++)
        p[i] = 0;
}

static __always_inline void emit_net_event(__u32 uid, __u8 op, __u8 status,
                                           const struct net_target *t,
                                           const char *executable_path,
                                           const char *policy_id)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    struct task_struct *task;
    struct tty_struct *tty = 0;
    struct mm_struct *mm = 0;
    unsigned long arg_start = 0, arg_end = 0;
    __u32 cmdline_len = 0;

    if (!e) return;
    /* Zero up front so the fixed-size string fields and the struct padding
     * never carry stale ring-buffer bytes past their NUL into userspace. */
    zero_net_event(e);
    e->uid = uid;
    e->real_uid = (__u32)bpf_get_current_uid_gid();
    e->operation = op;
    e->status = status;
    e->create_timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->family = t->family;
    e->protocol = t->protocol;
    e->sock_type = t->sock_type;
    e->addr_valid = t->has_addr;
    if (t->is_remote) {
        e->remote_port = t->port;
        __builtin_memcpy(e->remote_addr, t->addr, 16);
    } else {
        e->local_port = t->port;
        __builtin_memcpy(e->local_addr, t->addr, 16);
    }
    task = (struct task_struct *)bpf_get_current_task_btf();
    e->audit_session_id = BPF_CORE_READ(task, sessionid);
    fill_cgroup(e, task);
    {
        struct task_struct *parent;

        parent = task->real_parent;
        if (parent)
            e->ppid = parent->tgid;
    }
    BPF_CORE_READ_INTO(&tty, task, signal, tty);
    if (tty) BPF_CORE_READ_STR_INTO(&e->tty, tty, name);
    BPF_CORE_READ_INTO(&mm, task, mm);
    if (mm) {
        BPF_CORE_READ_INTO(&arg_start, mm, arg_start);
        BPF_CORE_READ_INTO(&arg_end, mm, arg_end);
        if (arg_end > arg_start) {
            unsigned long arg_len = arg_end - arg_start;

            cmdline_len = arg_len > CMDLINE_LEN ? CMDLINE_LEN : (__u32)arg_len;
            if (bpf_probe_read_user(e->cmdline, cmdline_len, (void *)arg_start) == 0)
                e->cmdline_len = cmdline_len;
        }
    }
    if (t->path)
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), t->path);
    if (executable_path)
        bpf_probe_read_kernel_str(e->executable_path, sizeof(e->executable_path),
                                  executable_path);
    if (policy_id)
        bpf_probe_read_kernel_str(e->policy_id, sizeof(e->policy_id), policy_id);
    bpf_ringbuf_submit(e, 0);
}

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
    __u8 op;
    __u8 perm_bit;
    __u8 matched;
    __u8 exec_resolved; /* current process image was resolved via bpf_d_path */
    __u8 status;
    __u8 emit;
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
    __u8 denied;

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
    cfg = bpf_map_lookup_elem(&net_runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    ctx->status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    ctx->emit = !r->no_event;
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
    inner = bpf_map_lookup_elem(&active_net_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    exec_scratch = bpf_map_lookup_elem(&net_exec_path_scratch, &zero);
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
        /* Two hash lookups per check, next to the bpf_d_path above that costs
         * considerably more. Policies with no name-scoped rules still pay them,
         * but never consult the result. */
        .employee_id = current_employee_id(task, uid),
        .uid = uid,
        .count = count,
        .exec_path_len = exec_path_len,
        .op = op,
        .perm_bit = perm_bit,
        .exec_resolved = exec_resolved,
    };
    bpf_loop(MAX_RULES, check_net_rule_cb, &ctx, 0);
    if (ctx.matched && ctx.emit)
        emit_net_event(uid, op, ctx.status, t, executable_path, meta->meta.id);
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

/*
 * ===========================================================================
 * Ingress evaluation
 * ===========================================================================
 */
struct ingress_ctx {
    __u8 src[16];
    __u8 local[16];
    __u32 count;
    __u16 sport;
    __u16 lport;
    __u8 family;
    __u8 matched;
    __u8 status;
    __u8 emit;
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
    __u8 denied;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(&ingress_policy, &index);
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
    cfg = bpf_map_lookup_elem(&net_runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    ctx->status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    ctx->emit = !r->no_event;
    /* Any non-zero return makes tcp_conn_request() drop the SYN. The client
     * sees a timeout rather than a refusal — there is no way to answer from
     * here, and staying silent is the conventional behaviour for a filtered
     * port anyway. */
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Emit an ingress record. Deliberately not emit_net_event(): that one reads
 * current's cgroup, tty and argv, none of which mean anything in softirq. */
static __always_inline void emit_ingress_event(const struct ingress_ctx *ctx, __u8 status,
                                               const char *policy_id)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);

    if (!e) return;
    zero_net_event(e);
    e->operation = OP_NET_INGRESS;
    e->status = status;
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

    meta = bpf_map_lookup_elem(&ingress_policy, &zero);
    if (!meta) return 0;
    ctx->count = meta->meta.rule_count;
    if (ctx->count > MAX_RULES) ctx->count = MAX_RULES;
    if (ctx->count == 0) return 0;

    bpf_loop(MAX_RULES, check_ingress_rule_cb, ctx, 0);
    if (!ctx->matched || !ctx->emit) return ctx->result;

    cfg = bpf_map_lookup_elem(&net_runtime_config_map, &zero);
    gen = cfg ? cfg->generation : 0;
    __builtin_memcpy(seen.src, ctx->src, 16);
    seen.sport = ctx->sport;
    seen.lport = ctx->lport;
    prev = bpf_map_lookup_elem(&ingress_seen, &seen);
    if (prev && *prev == gen) return ctx->result;  /* a SYN retransmit */
    bpf_map_update_elem(&ingress_seen, &seen, &gen, BPF_ANY);
    emit_ingress_event(ctx, ctx->status, meta->meta.id);
    return ctx->result;
}

/*
 * ===========================================================================
 * Hooks
 * ===========================================================================
 */

/* Inbound TCP, judged at the SYN before any connection state is committed.
 *
 * Runs in softirq: there is no current task, so nothing here may call
 * bpf_get_current_*. Everything needed is already on the request_sock, which
 * tcp_conn_request() fills in via af_ops->init_req() immediately before calling
 * this hook — no sk_buff parsing required. sk is the listening socket.
 *
 * task_is_exempt() is deliberately absent. Ingress is a host-wide policy with
 * no user behind it, so there is no session to exempt. */
SEC("lsm/inet_conn_request")
long BPF_PROG(check_net_ingress, struct sock *sk, struct sk_buff *skb,
              struct request_sock *req, int ret)
{
    /* Not named ctx: BPF_PROG's expansion already binds that identifier. */
    struct ingress_ctx ic = {};
    __u16 family;

    if (ret) return lsm_ret(ret);
    family = BPF_CORE_READ(req, __req_common.skc_family);
    if (family == AF_INET) {
        /* On a request_sock, skc_daddr is ir_rmt_addr (the client) and
         * skc_rcv_saddr is ir_loc_addr (the address it reached us on). */
        set_v4_mapped(ic.src, BPF_CORE_READ(req, __req_common.skc_daddr));
        set_v4_mapped(ic.local, BPF_CORE_READ(req, __req_common.skc_rcv_saddr));
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&ic.src, req, __req_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&ic.local, req, __req_common.skc_v6_rcv_saddr);
    } else {
        return 0;
    }
    ic.family = (__u8)family;
    ic.lport = BPF_CORE_READ(req, __req_common.skc_num);              /* host order */
    ic.sport = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport)); /* big endian */
    return lsm_ret(check_ingress(&ic));
}

/* socket() and socketpair(). The only hook that sees raw/ICMP sockets before
 * they can do anything, which makes it the practical lever for those: a raw
 * socket has no ports and its sendmsg destinations are weak evidence.
 *
 * A protocol of 0 means "the default for this family and type", which is what
 * socket(AF_INET, SOCK_STREAM, 0) passes. Normalizing it to TCP/UDP here is
 * what makes a {"protocol": "tcp", "permission": create} rule behave the way it
 * reads. SOCK_RAW is left alone: 0 there means IPPROTO_IP, not a default. */
SEC("lsm/socket_create")
long BPF_PROG(check_net_create, int family, int type, int protocol, int kern, int ret)
{
    struct net_target t = {};

    if (ret) return lsm_ret(ret);
    /* Kernel-internal sockets (NFS, cifs, kernel TLS, ...) are not user policy
     * and must never be blocked. */
    if (kern) return 0;
    if (task_is_exempt()) return 0;

    t.family = (__u8)family;
    t.sock_type = (__u8)type;
    t.protocol = (__u8)protocol;
    if (protocol == 0 && (family == AF_INET || family == AF_INET6)) {
        if (type == SOCK_STREAM) t.protocol = IPPROTO_TCP;
        else if (type == SOCK_DGRAM) t.protocol = IPPROTO_UDP;
    }
    return lsm_ret(check_net_policy(&t, OP_NET_CREATE, NPERM_CREATE));
}

SEC("lsm/socket_bind")
long BPF_PROG(check_net_bind, struct socket *sock, struct sockaddr *address,
              int addrlen, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(address, addrlen, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_BIND, NPERM_BIND));
}

SEC("lsm/socket_listen")
long BPF_PROG(check_net_listen, struct socket *sock, int backlog, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    if (read_sock_local(sock, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_LISTEN, NPERM_LISTEN));
}

/* The peer is deliberately absent here: this hook runs before accept()
 * completes, so newsock carries no peer address yet. Inbound connections are
 * therefore judged on the listening socket's own address — which port was
 * opened — and per-peer inbound filtering is out of scope. */
SEC("lsm/socket_accept")
long BPF_PROG(check_net_accept, struct socket *sock, struct socket *newsock, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    if (read_sock_local(sock, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_ACCEPT, NPERM_ACCEPT));
}

/* Covers AF_UNIX as well as IP: security_socket_connect runs for every family,
 * and by then the sockaddr has been copied into kernel memory, so a
 * sockaddr_un's sun_path is readable straight from the argument. That is why
 * there is no unix_stream_connect hook here. */
SEC("lsm/socket_connect")
long BPF_PROG(check_net_connect, struct socket *sock, struct sockaddr *address,
              int addrlen, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(address, addrlen, &t, pb->path) < 0) return 0;
    t.is_remote = 1;
    return lsm_ret(check_net_policy(&t, OP_NET_CONNECT, NPERM_CONNECT));
}

/*
 * The only hook on the data path, so it defends itself in three stages:
 *
 *  1. msg_name == NULL means the destination was fixed by connect() and already
 *     judged there. Every TCP send and every connected-UDP send exits here, at
 *     the cost of one field read.
 *  2. An IP destination is looked up in net_verdict_cache, keyed by socket and
 *     destination; a hit for the current policy generation skips the rule scan
 *     entirely. This is what makes a sendto() loop to one collector cheap.
 *  3. Only a cache miss runs the full policy scan, and it caches the result.
 *
 * The cache also throttles events: one record per (socket, destination,
 * generation) instead of one per datagram. AF_UNIX destinations skip the cache
 * because a path does not fit the key, and hashing one risks a collision
 * silently deciding an access.
 */
SEC("lsm/socket_sendmsg")
long BPF_PROG(check_net_sendmsg, struct socket *sock, struct msghdr *msg,
              int size, int ret)
{
    __u32 zero = 0, gen = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;
    struct net_runtime_config *cfg;
    struct net_cache_key key = {};
    struct net_cache_val *val, nv = {};
    void *name;
    int addrlen, r;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    name = BPF_CORE_READ(msg, msg_name);
    if (!name) return 0;
    addrlen = BPF_CORE_READ(msg, msg_namelen);

    pb = bpf_map_lookup_elem(&net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(name, addrlen, &t, pb->path) < 0) return 0;
    t.is_remote = 1;

    cfg = bpf_map_lookup_elem(&net_runtime_config_map, &zero);
    gen = cfg ? cfg->generation : 0;

    if (t.has_addr && t.sk) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u32 uid = BPF_CORE_READ(task, loginuid.val);
        /* Two people on a shared account have the same login uid, so the
         * session is what tells their verdicts apart. */
        __u32 sid = BPF_CORE_READ(task, sessionid);

        key.sk = t.sk;
        val = bpf_map_lookup_elem(&net_verdict_cache, &key);
        if (val && val->generation == gen && val->uid == uid &&
            val->session_id == sid &&
            val->port == t.port && addrs_equal(val->addr, t.addr))
            return lsm_ret(val->verdict ? -13 /* EACCES */ : 0);

        r = check_net_policy(&t, OP_NET_SEND, NPERM_CONNECT);
        nv.generation = gen;
        nv.uid = uid;
        nv.session_id = sid;
        __builtin_memcpy(nv.addr, t.addr, 16);
        nv.port = t.port;
        nv.verdict = r ? 1 : 0;
        nv.emitted = 1;
        bpf_map_update_elem(&net_verdict_cache, &key, &nv, BPF_ANY);
        return lsm_ret(r);
    }
    return lsm_ret(check_net_policy(&t, OP_NET_SEND, NPERM_CONNECT));
}

/* Drop the socket's cached verdict before the kernel can hand its memory to a
 * new socket. Without this the cache key — a bare struct sock pointer — would
 * alias across sockets and leak one process's verdict to another. */
SEC("lsm/sk_free_security")
void BPF_PROG(check_net_sk_free, struct sock *sk)
{
    struct net_cache_key key = { .sk = (__u64)(unsigned long)sk };

    bpf_map_delete_elem(&net_verdict_cache, &key);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
