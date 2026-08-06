/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:37-99, before the split. */
#ifndef DOOR_NET_CONST_H
#define DOOR_NET_CONST_H

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
#define POLICY_ID_LEN 40
#define EMPLOYEE_NAME_LEN 64
/* Reporting-only strings on the session record; this object never reads them
 * and declares them only so its copy of the struct has the right size. See
 * door/file_const.h. */
#define SESSION_SERVICE_LEN 32
#define SESSION_RHOST_LEN   64
#define EMPLOYEE_ID_ANY 0
/* Where the login session came from. Copied from door/file_const.h, which
 * carries the reasoning; the two objects share no header, only the layouts and
 * the id spaces they both describe — the same terms struct session_identity is
 * duplicated on. The values are an interface with pam/pam.c and with every
 * rule the loader encodes, so the two copies must agree. */
#define ORIGIN_UNKNOWN   0u
#define ORIGIN_REMOTE    1u
#define ORIGIN_CONSOLE   2u
#define ORIGIN_SCHEDULED 3u
#define ORIGIN_SERVICE   4u
#define ORIGIN_MAX       ORIGIN_SERVICE
#define ORIGIN_BIT(x) ((__u8)(1u << (x)))
/* The origin field's high bits are flags; SESSION_CLOSED marks a session whose
 * login has ended while its processes live on. Copied from door/file_const.h,
 * which carries the reasoning, on the same terms as the values above. This
 * object never branches on the flag — it only has to mask it off before reading
 * the origin, which ORIGIN_VALUE is for. */
#define SESSION_CLOSED   (1u << 31)
#define ORIGIN_VALUE(x)  ((x) & 0xffu)
#define MAX_RULES 512
/* Slot 0 of an inner policy map holds the metadata, so a rule always sits at
 * 1 + its position in the config array and slot 0 can never name one — which is
 * what makes it the event's "no rule matched" value. A second copy of file.c's
 * definition: the two objects share no header, only the layouts they both
 * describe, the same way struct session_identity is duplicated below. */
#define RULE_SLOT_NONE 0u
/* The host fallback policy's reserved key in wax_active_net_policy_by_uid. A
 * second copy of file.c's definition on the same terms as RULE_SLOT_NONE above,
 * and it must KEEP IN SYNC: the two objects install from one loader, so a
 * disagreement here would leave the network rules of a fallback policy silently
 * unreachable while its file rules worked. door/file_const.h carries the
 * reasoning, including why the entry functions guard this value explicitly. */
#define FALLBACK_UID 0xFFFFFFFFu
#define MAX_CGROUP_DEPTH 32
#define MODE_ENFORCE 0
#define MODE_WARN    1

/* Network operation codes. file.c owns 1..13 for file-class operations; both
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
 * namespace of its own; it is unrelated to file.c's execute/read/write bits.
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

/* net_rule::no_event_s and ::no_event_fw are masks over the NPERM_* bits,
 * naming the operations whose 'S', and whose 'F' and 'W', this rule does not
 * report. Per operation, not per rule: a rule carrying NPERM_BIND|NPERM_LISTEN
 * can drop the bind noise and keep the listen record.
 *
 * ingress_rule::no_event is the exception and still carries the two status bits
 * below. An ingress rule judges one operation class, so there is no axis to key
 * a mask on; net_ingress.h expands the pair at the one call site.
 *
 * Copied from door/file_const.h; the two objects share no header. */
#define NO_EVENT_SUCCESS 1  /* suppress 'S' */
#define NO_EVENT_DENY    2  /* suppress 'F' and 'W' */

/* The one place the two masks are applied. Copied from door/file_const.h — see
 * there for what eff is, why silence takes naming every demanded operation, and
 * why the select costs the verifier nothing. Both callers here store the result
 * on the context rather than acting on it: the emit happens after bpf_loop, so
 * what the callback decided has to survive it. */
static __always_inline int rule_emits(__u8 eff, __u8 no_event_s,
                                      __u8 no_event_fw, __u8 status)
{
    __u8 suppressed = (status == 'S') ? no_event_s : no_event_fw;

    return (eff & ~suppressed) != 0;
}

#endif /* DOOR_NET_CONST_H */
