// SPDX-License-Identifier: GPL-2.0 OR MIT
// Dual-licensed; the kernel-facing license string stays GPL-compatible
// ("Dual MIT/GPL") so gpl_only helpers such as bpf_d_path remain usable.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Split into door/file_*.h purely for readability: this is still ONE
 * translation unit, and the order below reproduces file.c's original
 * top-to-bottom order exactly. Nothing in these fragments is forward-declared —
 * there is not a single prototype in the whole object — so reordering them will
 * not compile. Each header names the line range it was lifted from. */
#include "file_const.h"    /* also op_perm_mask() */
#include "file_types.h"
#include "file_maps.h"
#include "file_match.h"
#include "file_cgroup.h"
#include "file_event.h"
#include "file_policy.h"   /* also task_is_exempt() */
#include "file_path.h"     /* also lsm_ret() */
#include "file_proc.h"
#include "file_cred.h"     /* also #define CRED_ID_SLOTS */
#include "file_progs.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
