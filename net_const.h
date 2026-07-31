/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:37-99. */
#ifndef DOOR_NET_CONST_H
#define DOOR_NET_CONST_H

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
#define POLICY_ID_LEN 40
#define EMPLOYEE_NAME_LEN 64
#define EMPLOYEE_ID_ANY 0
#define MAX_RULES 512
/* Slot 0 of an inner policy map holds the metadata, so a rule always sits at
 * 1 + its position in the config array and slot 0 can never name one — which is
 * what makes it the event's "no rule matched" value. A second copy of door.c's
 * definition: the two objects share no header, only the layouts they both
 * describe, the same way struct session_identity is duplicated below. */
#define RULE_SLOT_NONE 0u
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

#endif /* DOOR_NET_CONST_H */
