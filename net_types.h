/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:100-363. */
#ifndef DOOR_NET_TYPES_H
#define DOOR_NET_TYPES_H

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
     * where wax_check_sendmsg below is the program that made that necessary.
     * EMPLOYEE_ID_ANY constrains nobody. */
    __u32 employee_id;
    __u8 addr[16];
    __u8 enabled;
    __u8 permission;    /* NPERM_* bitmask */
    __u8 deny;
    /* NPERM_* masks, not status bits: the operations whose 'S', and whose 'F'
     * and 'W', this rule does not report. See rule_emits(). */
    __u8 no_event_s;
    __u8 exec_suffix_len;
    __u8 path_suffix_len;
    __u8 family;        /* 0=any, AF_UNIX 1, AF_INET 2, AF_INET6 10 */
    __u8 protocol;      /* 0=any, IPPROTO_* */
    __u8 sock_type;     /* 0=any, SOCK_STREAM 1, SOCK_DGRAM 2, SOCK_RAW 3 */
    __u8 prefix_len;    /* 0..128, or NET_ANY_PREFIX */
    /* This one rule is observe-only; see door.c's struct policy_meta for the
     * three scopes. Came out of the tail padding, so port_min did not move. */
    __u8 warn;
    /* Took the byte warn left, on the same terms: port_min still does not move
     * and the size below is unchanged. */
    __u8 no_event_fw;
    __u16 port_min;     /* host byte order, inclusive */
    __u16 port_max;
    /* Which session origins this rule covers: a mask of ORIGIN_BIT(ORIGIN_*),
     * or 0 for "any origin". See struct rule::origin_mask in door/file_types.h.
     *
     * Appended after port_max rather than squeezed in ahead of it. There was no
     * padding left to take, so either way the struct grows to 616 — and putting
     * it last is what keeps port_min and port_max where cmd/wdog/net.go already
     * writes them. */
    __u8 origin_mask;   /* 612 */
    __u8 _pad[3];       /* 613 */
};                      /* 616 */

/* Slot 0 of every per-uid net policy. warning is door.c's struct policy_meta
 * field, at the same offset and with the same meaning: the whole policy becomes
 * observe-only, its deny rules reported 'W' and not enforced. See door.c for
 * why it lives in the meta rather than on each rule, and why the last byte of
 * id is not a usable home for it. */
struct net_policy_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN]; /* NUL-terminated policy id */
    __u8 warning;           /* 44 — deny rules report 'W' and are not enforced */
};

_Static_assert(__builtin_offsetof(struct net_policy_meta, warning) == 44,
               "net_policy_meta.warning must stay at offset 44 (cmd/wdog/file.go)");

/* Copied from door.c — the two objects must agree on these layouts byte for
 * byte, because they share the pinned maps holding them. See door.c for the
 * rationale on login_uid, on origin, and on the zero-padding invariant.
 *
 * This object reads origin and nothing else of what was added with it: service
 * and rhost are declared here purely so the struct has the size the shared map
 * was created with.
 *
 * origin's low byte is the origin and its high bits are flags — read it through
 * ORIGIN_VALUE(). This object never branches on SESSION_CLOSED; it only has to
 * mask it off, or every session whose login has ended would read as unknown. */
struct session_identity {
    char employee_name[EMPLOYEE_NAME_LEN];  /*   0 */
    __u32 login_uid;                        /*  64 */
    __u32 origin;                           /*  68 — ORIGIN_* | flags, was _pad */
    __u64 login_time_ns;                    /*  72 */
    char service[SESSION_SERVICE_LEN];      /*  80 — reporting only; unread here */
    char rhost[SESSION_RHOST_LEN];          /* 112 — reporting only; unread here */
};                                          /* 176 */

_Static_assert(sizeof(struct session_identity) == 176,
               "session_identity is the pinned wax_session_identity value; its size is an "
               "interface with pam/pam.c and cmd/wdog/session.go");
_Static_assert(__builtin_offsetof(struct session_identity, login_time_ns) == 72,
               "session_identity.login_time_ns must stay at offset 72 (pam/pam.c)");
_Static_assert(__builtin_offsetof(struct session_identity, origin) == 68,
               "session_identity.origin must stay at offset 68 (pam/pam.c)");

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
    /* Which rule of policy_id below decided this: the inner-map slot it
     * occupied, i.e. 1 + its position in the policy's rule array, or
     * RULE_SLOT_NONE. Userspace subtracts the one; see cmd/wdog/file.go's
     * ruleIndex. For OP_NET_INGRESS it indexes the host-wide ingress policy's
     * rules, for every other operation the uid's netRules.
     *
     * This is the reserved hole _pad2 held. The record has no tail padding to
     * grow into — see the 1472 below — so taking the hole is what keeps every
     * offset after it, and both asserts, exactly where they were. */
    __u32 rule_slot;           /*   84 */
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
 * wax_check_sk_free() removes the entry when the socket is destroyed: the
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
    /* The two status bits, NOT the per-operation masks net_rule carries: an
     * ingress rule judges one operation class, so there is no axis to key a
     * mask on. check_ingress_rule_cb expands this into the pair rule_emits()
     * takes; see net_const.h. */
    __u8 no_event;          /* NO_EVENT_* status mask */
    __u8 family;            /* 0=any, AF_INET 2, AF_INET6 10 */
    __u8 protocol;          /* 0=any, IPPROTO_TCP 6; only TCP arrives here today */
    __u8 src_prefix_len;    /* 0..128, or NET_ANY_PREFIX */
    __u8 local_prefix_len;
    /* This one rule is observe-only; see door.c's struct policy_meta. It took
     * the last padding byte, so port_min did not move but the struct is now
     * exactly full: the next flag grows it to 46. That still fits the 48-byte
     * slot the meta already sets, so unlike cred_rule it would NOT be caught by
     * a value-size mismatch — only by the assert below. */
    __u8 warn;
    __u16 port_min;         /* local (listening) port, host byte order */
    __u16 port_max;
};

struct ingress_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN];
    __u8 warning;           /* 44 — deny rules report 'W' and are not enforced */
};

_Static_assert(__builtin_offsetof(struct ingress_meta, warning) == 44,
               "ingress_meta.warning must stay at offset 44 (cmd/wdog/ingress.go)");

/* The one policy space whose slot the meta's warning byte actually grew.
 * Everywhere else the union is dominated by a rule struct hundreds of bytes
 * wide, but ingress_meta and ingress_rule were both exactly 44, so the meta now
 * sets the size. No ingress_rule field moved — only the map's value size, which
 * cmd/wdog/ingress.go's kernelIngressSlot has to match. Both numbers are pinned
 * below. */
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
_Static_assert(sizeof(struct net_rule) == 616, "struct net_rule must stay 616 bytes");
/* sizeof cannot catch two adjacent __u8s swapping places, and deny, no_event_s,
 * warn and no_event_fw are four indistinguishable bytes whose meanings are not
 * interchangeable. Same treatment as door.c's struct rule. no_event_fw took the
 * struct's last padding byte, and origin_mask is what the note there predicted:
 * it grew the struct 612 -> 616. It went on the END so that port_min and
 * port_max, which the loader writes by offset, did not move — pin all four. */
_Static_assert(__builtin_offsetof(struct net_rule, warn) == 606,
               "net_rule.warn must stay at offset 606 (cmd/wdog/net.go)");
_Static_assert(__builtin_offsetof(struct net_rule, no_event_fw) == 607,
               "net_rule.no_event_fw must stay at offset 607 (cmd/wdog/net.go)");
_Static_assert(__builtin_offsetof(struct net_rule, port_min) == 608,
               "net_rule.port_min must stay at offset 608 (cmd/wdog/net.go)");
_Static_assert(__builtin_offsetof(struct net_rule, origin_mask) == 612,
               "net_rule.origin_mask must stay at offset 612 (cmd/wdog/net.go)");
_Static_assert(sizeof(struct net_event) == 1472, "struct net_event must stay 1472 bytes");
_Static_assert(sizeof(struct net_event) % 8 == 0, "zero_net_event needs a multiple of 8");
/* rule_slot took over a hole that already existed, which is why the 1472 above
 * did not have to move. Pin that: a field inserted ahead of it would hold the
 * size by consuming the hole elsewhere and silently shift every offset
 * cmd/wdog/net_test.go hard-codes. */
_Static_assert(__builtin_offsetof(struct net_event, rule_slot) == 84,
               "net_event.rule_slot must stay at offset 84 (cmd/wdog/net_test.go)");
_Static_assert(sizeof(struct ingress_rule) == 44, "struct ingress_rule must stay 44 bytes");
_Static_assert(__builtin_offsetof(struct ingress_rule, warn) == 39,
               "ingress_rule.warn must stay at offset 39 (cmd/wdog/ingress.go)");
/* 48, not the rule's 44: ingress_meta gained a warning byte at offset 44 and is
 * now the wider member of the union. See struct ingress_slot. */
_Static_assert(sizeof(struct ingress_slot) == 48, "struct ingress_slot must stay 48 bytes");

#endif /* DOOR_NET_TYPES_H */
