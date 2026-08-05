// SPDX-License-Identifier: GPL-2.0 OR MIT
// The self-defense object: libwdoors.lsm, the third of three (f=file, n=net,
// s=self). It protects wdog, Agent, their BPF objects and the state they depend
// on — there is no policy here, no rule, and nothing here decides anything about
// a user.
//
// It does make ONE observation about users, and the exception is stated rather
// than hidden. The session identity map is already this object's business: it is
// the one map the guard deliberately lets an outsider open, and wax_self_bpf_map
// already reports every such open. Pairing that open with the bpf(2) command
// that follows it (wax_self_bpf, self_session_record) turns "someone opened the
// identity map" into "session 42 logged in" — a login and logout event nothing
// else in the system is placed to see. That is an observation, not a decision:
// SOP_LOGIN and SOP_LOGOUT sit outside the self-defense op range on purpose, so
// unlike everything else this object emits, Agent's eventFilter CAN hide them.
// See door/self_const.h and the note in door/self_event.h.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A SEPARATE OBJECT AND NOT PART OF door/file.c
//
// Three properties, and only the first is about tidiness:
//
//  1. ARMING LATENCY. Verifying the file object takes the better part of a
//     minute, nearly all of it verifier time. Until it finishes, `pkill wdog`
//     and `bpftool map delete` both work. This object has no bpf_loop over
//     policy, no bpf_d_path, no glob matcher and no 1440-byte event, so it loads
//     and attaches in about a second — and wdog attaches it FIRST. The
//     undefended window shrinks from ~45s to ~1s, which matters more once a
//     supervisor is restarting wdog on its own.
//  2. IT CANNOT BE DESELECTED. fileHooks is a supported way to run on a kernel
//     missing an attach point (docs/build.md). A hole in the daemon's protection
//     of itself is not the same kind of thing, so it lives behind a different
//     option with a different default.
//  3. VERIFIER BUDGET. wax_check_sendmsg in the network object came close to the
//     million-instruction ceiling on 5.14. Nothing here can push it closer.
//
// Attach ORDER buys arming latency and nothing else, and it is worth saying so
// before someone "optimises" it away: BPF LSM programs are attached as
// BPF_TRAMP_MODIFY_RETURN and invoke_bpf_mod_ret() short-circuits on the first
// non-zero return, so a deny from this object wins over a permissive program
// regardless of which attached first. That is also why an attacker cannot
// neutralise anything here by attaching their own LSM program returning 0.
//
// ---------------------------------------------------------------------------
// COPIED FROM door/file.c — KEEP IN SYNC. Only two things, and the shortness of
// this list is the design:
//
//   lsm_ret()        door/file_path.h   ->  door/self_check.h
//   NSEC_PER_CLOCK   door/file_const.h  ->  door/self_const.h
//
// DELIBERATELY NOT COPIED, and it has to stay that way:
//
//   task_is_exempt()   door/file_policy.h — this object exists precisely to
//     judge the tasks that one waves through. A systemd-started task with
//     sessionid -1 is the ATTACKER here, not an exempt daemon. If that function
//     ever appears in this file the whole layer is defeated in one line.
//   bpf_d_path, the glob matchers, struct rule, the policy maps — none of them.
//     Every check below is O(1) on scalars, because every check below runs on
//     hooks that ALSO carry a policy program. See docs/self-defense.md.
// ---------------------------------------------------------------------------
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* One translation unit, same as door/file.c and door/net.c. Nothing here is
 * forward-declared, so reordering these will not compile. */
#include "self_const.h"
#include "self_types.h"
#include "self_maps.h"
#include "self_event.h"
#include "self_check.h"   /* also lsm_ret() */
#include "self_progs.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
