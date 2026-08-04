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
//   struct session_identity, struct employee_name_key, current_session_axes()
//   the wax_session_identity and wax_employee_ids maps (SHARED via their pins, not
//   merely duplicated — the declarations must stay byte-identical)
//   task_is_exempt()                                door.c:591-596
//   kernfs_node_parent(), cgroup_walk_cb()          door.c:319-381
//   fill_cgroup()   (retargeted at struct net_event)
//   zero_event()    (retargeted at struct net_event)
//   PATH_LEN / TTY_LEN / CMDLINE_LEN / POLICY_ID_LEN / MAX_RULES /
//   MAX_CGROUP_DEPTH / MODE_ENFORCE / MODE_WARN
//   NO_EVENT_SUCCESS / NO_EVENT_DENY / rule_emits()  file_const.h
// ---------------------------------------------------------------------------
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Split into door/net_*.h purely for readability: this is still ONE translation
 * unit, and the order below reproduces net.c's original top-to-bottom order
 * exactly. Nothing in these fragments is forward-declared — there is not a
 * single prototype in the whole object — so reordering them will not compile.
 * Each header names the line range it was lifted from. */
#include "net_const.h"    /* also rule_emits() */
#include "net_types.h"
#include "net_maps.h"
#include "net_match.h"
#include "net_sock.h"
#include "net_cgroup.h"
#include "net_event.h"
#include "net_policy.h"   /* also task_is_exempt(), lsm_ret() */
#include "net_ingress.h"
#include "net_progs.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
