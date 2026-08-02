/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:156-495. */
#ifndef DOOR_FILE_TYPES_H
#define DOOR_FILE_TYPES_H

/* A rule matches when the current process image matches exec_path, the target
 * matches path, and the rule's permission intersects the mask op_perm_mask()
 * returns for the operation being judged. Patterns are stored
 * unescaped; the wild bitmaps mark which positions are '?'/'*' wildcards, so a
 * literal '*' or '?' byte (escaped in JSON) has its bit clear. An empty
 * pattern (leading NUL, bit 0 clear) always matches.
 *
 * A pattern whose first byte is a wildcard '*' is a suffix match. The loader
 * fills the matching *_suffix_len with the number of pattern bytes after that
 * '*', which is what lets the matcher jump straight to the path's tail instead
 * of backtracking. It is 0 for prefix and empty patterns.
 *
 * employee_id is the second user axis, alongside the login uid that selected
 * the policy: it scopes the rule to one person, so one policy on a shared
 * account can be split per employee. EMPLOYEE_ID_ANY means the rule constrains
 * no employee, which is what a rule that names none encodes to.
 *
 * It is an id rather than the name itself, and that is not an optimization —
 * it is what makes the rule loop verifiable. Comparing a name here means
 * branching on a pointer whose null-ness the verifier cannot know, and that
 * fork doubles the exploration of both glob matchers below it; measured on
 * RHEL 9 (5.14), it put wax_check_sendmsg in net.c past the one-million
 * instruction ceiling and the object stopped loading. A scalar compare costs
 * nothing. The loader interns each distinct name to an id and publishes the
 * mapping in wax_employee_ids, which check_policy consults once per check —
 * outside the loop, where one pointer branch is affordable. */
struct rule {
    char exec_path[PATH_LEN];
    char path[PATH_LEN];
    __u8 exec_wild[PATH_LEN / 8];
    __u8 path_wild[PATH_LEN / 8];
    __u32 employee_id;
    __u8 enabled;
    __u8 permission;
    __u8 deny;
    /* PERM_* masks, not status bits: the operations whose 'S' this rule does
     * not report. Same offset the whole-rule status mask used to sit at, and
     * deliberately so — see rule_emits(). */
    __u8 no_event_s;
    __u8 exec_suffix_len;
    __u8 path_suffix_len;
    /* This one rule is observe-only; see struct policy_meta::warning for the
     * three scopes and how they combine. Came out of the tail padding, so no
     * field moved and the size below did not change. */
    __u8 warn;
    /* The operations whose 'F' and 'W' this rule does not report. Took the last
     * padding byte on the same terms warn took the one before it, so no field
     * moved and the size below still did not change. */
    __u8 no_event_fw;
};

/* The userspace loader writes this by byte offset (cmd/wdog/file.go) and
 * file_test.go pins the size, so a silent layout change here would apply policy
 * to the wrong fields rather than fail to build. */
_Static_assert(sizeof(struct rule) == 588, "struct rule must stay 588 bytes");
/* sizeof alone cannot catch two adjacent __u8s swapping places, and deny,
 * no_event_s, warn and no_event_fw are four indistinguishable bytes whose
 * meanings are not interchangeable. Pin the two added last.
 *
 * no_event_fw is worth pinning for a second reason: it consumed the struct's
 * last padding byte, so the next flag added here grows struct rule to 592 and
 * therefore the map's value size, which the loader's Put rejects outright. */
_Static_assert(__builtin_offsetof(struct rule, warn) == 586,
               "rule.warn must stay at offset 586 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct rule, no_event_fw) == 587,
               "rule.no_event_fw must stay at offset 587 (cmd/wdog/file.go)");

/* A signal rule. Deliberately not struct rule: the thing being acted on is
 * another process, so the constraints describe a task rather than a path.
 *
 * exec_path is the SENDER's image and target_path the TARGET's, both matched
 * with the same glob syntax and matcher the file rules use. Neither can come
 * from bpf_d_path here — the helper is rejected at this attach point on RHEL 9
 * (measured: "helper call is not allowed") — so both are read out of wax_pid_image,
 * which the exec hook fills while d_path is still available. That indirection
 * is the whole reason wax_pid_image exists.
 *
 * signals is a bitmask of 1 << signo; 0 means the rule does not constrain the
 * signal. Signal 0 is the existence-check idiom (kill(pid, 0)) and is included
 * in "any", so a catch-all deny stops `kill -0` too — the loader warns about
 * that rather than silently carving it out. */
struct proc_rule {
    char exec_path[PATH_LEN];       /*   0 — sender's image */
    char target_path[PATH_LEN];     /* 256 — target's image */
    __u8 exec_wild[PATH_LEN / 8];   /* 512 */
    __u8 target_wild[PATH_LEN / 8]; /* 544 */
    __u64 signals;                  /* 576 — OP_KILL only */
    __u32 employee_id;              /* 584 — sender */
    __u32 target_employee_id;       /* 588 */
    __u32 target_uid;               /* 592 — target's real uid */
    __u8 has_target_uid;            /* 596 — target_uid is meaningful */
    __u8 enabled;                   /* 597 */
    __u8 deny;                      /* 598 */
    __u8 no_event_s;                /* 599 — PROC_OP_* mask: ops with no 'S' */
    __u8 exec_suffix_len;           /* 600 */
    __u8 target_suffix_len;         /* 601 */
    __u8 op_mask;                   /* 602 — PROC_OP_*_BIT; which ops this covers */
    __u8 ptrace_mode;               /* 603 — OP_PTRACE only; 0 = any mode */
    __u8 warn;                      /* 604 — this rule alone is observe-only */
    __u8 no_event_fw;               /* 605 — PROC_OP_* mask: ops with no 'F'/'W' */
    __u8 _pad[2];                   /* 606 */
};                                  /* 608 */

/* The two bytes came out of the tail padding, so the process controls did not
 * move a single field of the file rule they were modelled on. warn later came
 * out of the same padding, on the same terms, and no_event_fw after it —
 * this struct is the one that still has room to spare. */
_Static_assert(sizeof(struct proc_rule) == 608, "struct proc_rule must stay 608 bytes");
_Static_assert(__builtin_offsetof(struct proc_rule, warn) == 604,
               "proc_rule.warn must stay at offset 604 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct proc_rule, no_event_fw) == 605,
               "proc_rule.no_event_fw must stay at offset 605 (cmd/wdog/file.go)");

/* A credential-switch rule: the task changing its OWN user or group identity,
 * which is what su and sudo do once they are running.
 *
 * There is deliberately no "from" field. The source identity is the audit login
 * uid, and that is already the key wax_active_cred_policy_by_uid was looked up by —
 * a from_uid would either restate it or be dead. Read a rule as "the login uid
 * this policy belongs to may not acquire to_uid".
 *
 * The momentary real uid is not a usable source axis either: sudo runs a
 * permission state machine, and after its first hop old->uid is 0 for the rest
 * of the run, so a 1000 -> oracle switch never happens as a single hop. A rule
 * written against that would be perfectly formed and never match. The old real
 * id is reported on the event instead, where it says which hop tripped the rule.
 *
 * to_uid/to_gid match an id this call MOVES A SLOT TO — compared slot by slot
 * against the old credentials, so a rule catches both the real-uid move su
 * makes and the effective-uid move of a process that kept a saved uid and later
 * calls seteuid(0). Slots that do not move are ignored, which is what keeps the
 * no-op calls sudo makes by the dozen from matching anything. See
 * struct cred_id_delta for why this is slot-wise rather than "an id the task
 * did not already hold".
 *
 * exec_path cannot come from bpf_d_path — the helper is rejected at the
 * credential hooks exactly as it is at task_kill — so it is read out of
 * wax_pid_image, filled on exec where the helper is allowed. */
struct cred_rule {
    char exec_path[PATH_LEN];       /*   0 — the switching process's image */
    __u8 exec_wild[PATH_LEN / 8];   /* 256 */
    __u32 employee_id;              /* 288 */
    __u32 to_uid;                   /* 292 — OP_SETUID only */
    __u32 to_gid;                   /* 296 — OP_SETGID only */
    __u8 has_to_uid;                /* 300 — to_uid is meaningful */
    __u8 has_to_gid;                /* 301 — to_gid is meaningful */
    __u8 op_mask;                   /* 302 — CRED_OP_*_BIT; which ops this covers */
    __u8 enabled;                   /* 303 */
    __u8 deny;                      /* 304 */
    __u8 no_event_s;                /* 305 — CRED_OP_* mask: ops with no 'S' */
    __u8 exec_suffix_len;           /* 306 */
    __u8 warn;                      /* 307 — this rule alone is observe-only */
    __u8 no_event_fw;               /* 308 — CRED_OP_* mask: ops with no 'F'/'W' */
    __u8 _pad[3];                   /* 309 */
};                                  /* 312 */

/* warn took what had been the last padding byte, and no_event_fw is the field
 * the comment there predicted: 308 was 4·77 and employee_id forces 4-byte
 * alignment, so one more byte cost four and grew the map's value size.
 *
 * That growth is the design working, not a cost worked around. It is the only
 * observable signal that a wdog carrying per-operation noEvent is talking to a
 * BPF object that predates it — the other four rule structs kept their sizes —
 * and the loader turns it into a refusal to start rather than a policy applied
 * against bytes the kernel reads as something else. See checkObjectABI in
 * cmd/wdog/file.go. */
_Static_assert(sizeof(struct cred_rule) == 312, "struct cred_rule must stay 312 bytes");
_Static_assert(__builtin_offsetof(struct cred_rule, warn) == 307,
               "cred_rule.warn must stay at offset 307 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct cred_rule, no_event_fw) == 308,
               "cred_rule.no_event_fw must stay at offset 308 (cmd/wdog/file.go)");

/* Slot 0 of every inner policy map. warning makes the whole policy
 * observe-only: its deny rules are allowed through and reported 'W' instead of
 * 'F'.
 *
 * Observe-only has three scopes, and each site OR's all three:
 *
 *     runtime_config::mode   the whole host   — the emergency full release
 *     policy_meta::warning   one policy       — this field
 *     struct rule::warn      one rule         — the per-rule twin
 *
 * The verdict is identical whichever fires; only the blast radius differs. OR
 * and not override, in both directions: a rule cannot re-enforce itself under a
 * warning policy, and neither can hold out against `mode warn`, because that
 * switch has to stay a release of *everything* for the operator reaching for it
 * mid-incident. See docs/policy.md.
 *
 * This one stays in the meta rather than moving onto each rule. It describes the
 * policy, so a rule copy would replicate one bit across up to MAX_RULES slots
 * and say nothing the per-rule flag does not already say better. Here one offset
 * serves all five policy spaces, which is what lets a single loader function
 * write it everywhere (cmd/wdog/file.go's putMeta).
 *
 * Do not fold it into the last byte of id. POLICY_ID_LEN is 40 while the loader
 * writes at most 39 characters, so byte 43 looks free, but it is the NUL
 * terminator of a maximum-length id: a flag there would make
 * bpf_probe_read_kernel_str() run off the end of id and corrupt the event's
 * policy_id. */
struct policy_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN]; /* NUL-terminated policy id */
    __u8 warning;           /* 44 — deny rules report 'W' and are not enforced */
};

/* The loader writes warning by byte offset (cmd/wdog/file.go's putMeta), and
 * every policy space — file, proc, cred, net, ingress — shares this layout, so
 * a silent move here would apply the flag to the wrong field in five places at
 * once rather than fail to build. */
_Static_assert(__builtin_offsetof(struct policy_meta, warning) == 44,
               "policy_meta.warning must stay at offset 44 (cmd/wdog/file.go)");

struct proc_policy_slot {
    union {
        struct policy_meta meta;
        struct proc_rule rule;
    };
};

struct cred_policy_slot {
    union {
        struct policy_meta meta;
        struct cred_rule rule;
    };
};

/* A process's executable image, recorded while it can still be resolved.
 *
 * start_clock is start_boottime converted to the 1/100s units /proc/<pid>/stat
 * reports, so wdog can prime this map for processes that were already running
 * when it started and the two sides compare exactly. It guards against a stale
 * entry being read for a reused pid — the same job login_uid does in
 * wax_session_identity. */
struct pid_image {
    char exe_path[PATH_LEN];
    __u64 start_clock;
    __u32 path_len;     /* strlen, for suffix matching */
    __u32 _pad;
};

/* What PAM recorded for one audit session. pam_wood.so fills this at
 * open_session and removes it at close_session; wdog reaps records whose
 * session no longer has a live process.
 *
 * login_uid is not a matching criterion — it exists so a record left behind by
 * a session whose id has since been reused cannot lend its name to a different
 * user.
 *
 * INVARIANT: employee_name must be zero-padded to its full width, not merely
 * NUL-terminated. It is used as a hash-map key below, and a key is compared as
 * a fixed-size block of bytes — junk after the terminator would look up nothing
 * at all. pam_wood.c memsets the value before filling it for this reason. */
struct session_identity {
    char employee_name[EMPLOYEE_NAME_LEN];
    __u32 login_uid;
    __u32 _pad;
};

/* Key of the intern table: a name, padded to a fixed width so it can be hashed.
 * Deliberately the same layout as session_identity's leading field, so a
 * session record's name is looked up in place with no copy. */
struct employee_name_key {
    char name[EMPLOYEE_NAME_LEN];
};

struct policy_slot {
    union {
        struct policy_meta meta;
        struct rule rule;
    };
};

struct runtime_config { __u32 mode; };

struct event {
    __u32 uid;       /* audit login uid */
    __u32 real_uid;  /* real uid at time of operation */
    __u64 create_timestamp_ns;
    __u64 cgroup_id; /* cgroup v2 id (kernfs inode) */
    __u32 audit_session_id;
    __u8 status;
    __u8 operation;
    /* Both carved out of what was two bytes of padding, so neither addition
     * moved a field that file_test.go's pinned layout already names. signal is
     * OP_KILL only; setid_flags is OP_SETUID/OP_SETGID only and carries the
     * LSM_SETID_* family that made the change. */
    __u8 signal;
    __u8 setid_flags;
    char path[PATH_LEN];
    char executable_path[PATH_LEN];
    char cgroup[PATH_LEN]; /* cgroup v2 path, best-effort */
    char policy_id[POLICY_ID_LEN]; /* deciding policy; empty when the uid has no policy */
    char tty[TTY_LEN];
    __u32 pid;
    __u32 ppid;
    __u32 cmdline_len;
    char cmdline[CMDLINE_LEN];
    /* OP_SETUID/OP_SETGID only, and both describe the SAME id slot: the one
     * this call moved that the rule matched on. to_id is where it landed —
     * what the rule named — and from_id what that slot held before, which on a
     * multi-step switch such as sudo's says which hop tripped the rule. Drawing
     * the two from different slots would render an effective-uid change of
     * 1 -> 0 as "0 -> 0". Who the person is, is uid, the login uid above.
     *
     * These two went on the end rather than into the tail padding because there
     * were only four spare bytes there and this needs eight. The record's
     * declared length goes 1428 -> 1436 and its sizeof 1432 -> 1440. */
    __u32 from_id;
    __u32 to_id;
    /* Which rule of policy_id above decided this: the inner-map slot it
     * occupied, i.e. 1 + its position in the policy's rule array, or
     * RULE_SLOT_NONE. Userspace subtracts the one; see cmd/wdog/file.go's
     * ruleIndex. Which array it indexes follows from operation — file, proc and
     * cred rules are three separate lists.
     *
     * This is the four bytes of tail padding the note above says were too few
     * for from_id/to_id. Spending them costs nothing: sizeof was already 1440,
     * so the record does not grow, and the declared length now equals it. */
    __u32 rule_slot;
};

/* zero_event clears the record eight bytes at a time and bpf_ringbuf_reserve is
 * given sizeof(), so the total must stay a multiple of 8. The declared length
 * is now the whole 1440 — there is no tail padding left — and file_test.go pins
 * the offsets. */
_Static_assert(sizeof(struct event) == 1440, "struct event must stay 1440 bytes");
/* rule_slot went into padding that already existed, which is the whole reason
 * the assert above did not have to move. Pin that: a field inserted ahead of it
 * would keep sizeof at 1440 by eating the padding elsewhere and silently shift
 * every offset cmd/wdog/file_test.go hard-codes. */
_Static_assert(__builtin_offsetof(struct event, rule_slot) == 1436,
               "event.rule_slot must stay at offset 1436 (cmd/wdog/file_test.go)");

struct pending_exec_event {
    __u32 uid;
    __u8 status;
    __u8 _pad[3];
    char file[PATH_LEN];
    char executable_path[PATH_LEN];
    char policy_id[POLICY_ID_LEN];
    /* Carried to wax_emit_exec so a staged exec reports the same rule an
     * inline decision would. queue_exec_event takes it as a required argument
     * rather than defaulting it, because the percpu scratch this is staged
     * through is not cleared between execs — an unset field would report the
     * previous exec's rule on that CPU rather than none. */
    __u32 rule_slot;
};

struct executable_path_scratch {
    char path[PATH_LEN];
};

/* Twice PATH_LEN: appending a dentry name after a bpf_d_path result uses a
 * variable offset plus a fixed-size copy, and the verifier bounds that access
 * by the two worst cases added together. Rules never match past PATH_LEN. */
struct file_path_scratch {
    char path[PATH_LEN * 2];
};

/* Right-to-left dentry-walk buffer for hooks that only receive a dentry
 * (inode_setattr). Same 2x headroom rationale as wax_file_path_scratch. */
struct dentry_walk_scratch {
    char build[PATH_LEN * 2];
    char name[PATH_LEN];
};

#endif /* DOOR_FILE_TYPES_H */
