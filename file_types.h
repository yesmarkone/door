/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:156-495, before the split. */
#ifndef DOOR_FILE_TYPES_H
#define DOOR_FILE_TYPES_H

/* The key every per-uid policy map is looked up by. Both user axes that select
 * a policy live here: the login uid, and the employee PAM recorded on that
 * session. EMPLOYEE_ID_ANY (0) is the policy that names nobody — the one
 * everyone on that uid without a policy of their own falls to, including
 * sessions whose identity was never recorded.
 *
 * The employee is an interned id rather than the name itself, and that is not
 * an optimization. It is what keeps the lookup a scalar hash of eight bytes
 * instead of a 64-byte string compare in the path every hook takes. The loader
 * interns each distinct name and publishes the mapping in wax_employee_ids,
 * which current_session_axes() consults once per check.
 *
 * Two lookups, not an ordered scan: check_policy tries the caller's own
 * employee first and EMPLOYEE_ID_ANY second. So an employee-scoped policy
 * REPLACES the uid's unscoped one rather than layering over it, and each policy
 * has to carry its own catch-all. There is no order among policies — first
 * match wins applies inside one policy's rule array and nowhere else.
 *
 * The rule structs below carry no employee axis at all any more: selecting the
 * policy IS the employee match. That took a scalar compare out of every rule
 * loop, which is where this engine's instruction budget is actually spent. The
 * one exception is proc_rule::target_employee_id, which describes the other end
 * of a kill or ptrace and cannot be a property of the policy. */
struct policy_key {
    __u32 uid;
    __u32 employee_id;
};

_Static_assert(sizeof(struct policy_key) == 8, "struct policy_key must stay 8 bytes");
_Static_assert(__builtin_offsetof(struct policy_key, employee_id) == 4,
               "policy_key.employee_id must stay at offset 4 (cmd/wdog/main.go)");

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
 * There is no employee field. Who a rule applies to is settled before this
 * struct is ever read — struct policy_key above says how. */
struct rule {
    char exec_path[PATH_LEN];
    char path[PATH_LEN];
    __u8 exec_wild[PATH_LEN / 8];
    __u8 path_wild[PATH_LEN / 8];
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
    /* Which session origins this rule covers: a mask of ORIGIN_BIT(ORIGIN_*),
     * or 0 for "any origin". Zero is what every rule written before this axis
     * existed encodes to, which is what keeps their meaning bit for bit
     * unchanged.
     *
     * A mask rather than a single value so one rule can name "remote or
     * console" — the two human origins — without being written twice. It is a
     * plain scalar AND in the rule loop, and affordable there because the
     * session lookup that produces the value to test against happens ONCE per
     * check, outside the loop. See current_session_axes().
     *
     * This axis stayed on the rule when the employee axis moved to the policy
     * key, and the asymmetry is deliberate: one person's policy still needs
     * different rules for different origins ("kim.cs may edit /etc from the
     * console only"), and splitting that into two policies is impossible when
     * the key has no origin in it. */
    __u8 origin_mask;
    /* Padding, and also the size the loader's slot type is written against.
     * Three bytes is what keeps the struct a multiple of four now that
     * employee_id — its only multi-byte member — is gone and the natural
     * alignment is 1. */
    __u8 _pad[3];
};

/* The userspace loader writes this by byte offset (cmd/wdog/file.go) and
 * file_test.go pins the size, so a silent layout change here would apply policy
 * to the wrong fields rather than fail to build. */
_Static_assert(sizeof(struct rule) == 588, "struct rule must stay 588 bytes");
/* sizeof alone cannot catch two adjacent __u8s swapping places, and deny,
 * no_event_s, warn and no_event_fw are four indistinguishable bytes whose
 * meanings are not interchangeable. Pin the ones added last.
 *
 * ⚠ 588 is a size this struct has HELD BEFORE — it is what it was before
 * origin_mask grew it to 592. Dropping employee_id put it back, so a value size
 * of 588 no longer identifies a generation: an object predating the policy-key
 * change carries rules of exactly this width, and would read the four bytes at
 * 576 as an employee id while this loader writes enabled/permission/deny/
 * no_event_s there. What tells the two apart is the OUTER map's key size — 4
 * bytes when a policy was selected by uid alone, 8 now that it is selected by
 * (uid, employee). checkObjectABI in cmd/wdog/file.go checks both, and must
 * keep doing so; the same trap sits under struct cred_rule below and under
 * struct net_rule in door/net_types.h. */
_Static_assert(__builtin_offsetof(struct rule, warn) == 582,
               "rule.warn must stay at offset 582 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct rule, no_event_fw) == 583,
               "rule.no_event_fw must stay at offset 583 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct rule, origin_mask) == 584,
               "rule.origin_mask must stay at offset 584 (cmd/wdog/file.go)");

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
    /* The TARGET's employee, and the only employee id left on any rule. The
     * sender's moved into struct policy_key, but this one cannot follow it: the
     * policy is selected by the sender's login uid, while the target is a
     * different task on every call. "kim.cs may not kill lee.yh's processes but
     * may kill park.jh's" has to be two rules inside one policy. */
    __u32 target_employee_id;       /* 584 */
    __u32 target_uid;               /* 588 — target's real uid */
    __u8 has_target_uid;            /* 592 — target_uid is meaningful */
    __u8 enabled;                   /* 593 */
    __u8 deny;                      /* 594 */
    __u8 no_event_s;                /* 595 — PROC_OP_* mask: ops with no 'S' */
    __u8 exec_suffix_len;           /* 596 */
    __u8 target_suffix_len;         /* 597 */
    __u8 op_mask;                   /* 598 — PROC_OP_*_BIT; which ops this covers */
    __u8 ptrace_mode;               /* 599 — OP_PTRACE only; 0 = any mode */
    __u8 warn;                      /* 600 — this rule alone is observe-only */
    __u8 no_event_fw;               /* 601 — PROC_OP_* mask: ops with no 'F'/'W' */
    /* ORIGIN_BIT masks, 0 for "any origin". Two of them because this struct is
     * the one with a target axis: the sender's session origin and the target's
     * are independent questions, and "a scheduled job may not signal a remote
     * user's process" needs both halves. See struct rule::origin_mask. */
    __u8 origin_mask;               /* 602 — sender's session */
    __u8 target_origin_mask;        /* 603 — target's session */
    /* Four bytes of tail padding, back again: __u64 signals holds the struct's
     * alignment at 8, so dropping the sender's employee_id freed four bytes
     * that the size cannot give up. Read the warning under the size assert
     * before spending them. */
    __u8 _pad[4];                   /* 604 */
};                                  /* 608 */

/* ⚠ This is the one rule struct whose size did NOT change when the employee
 * axis moved to the policy key: __u64 signals pins the alignment at 8, so the
 * four bytes came back as padding. checkObjectABI therefore cannot tell a
 * current wdog from a stale libwdoorf.lsm by this map's value size alone — the
 * asserts below and the sibling structs in the same object (struct rule 592 ->
 * 588, struct cred_rule 312 -> 308) are what catch it. Exactly the failure mode
 * struct rule's note calls out: sizeof cannot see fields move within a struct
 * that stayed the same size. */
_Static_assert(sizeof(struct proc_rule) == 608, "struct proc_rule must stay 608 bytes");
_Static_assert(__builtin_offsetof(struct proc_rule, target_employee_id) == 584,
               "proc_rule.target_employee_id must stay at offset 584 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct proc_rule, warn) == 600,
               "proc_rule.warn must stay at offset 600 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct proc_rule, no_event_fw) == 601,
               "proc_rule.no_event_fw must stay at offset 601 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct proc_rule, origin_mask) == 602,
               "proc_rule.origin_mask must stay at offset 602 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct proc_rule, target_origin_mask) == 603,
               "proc_rule.target_origin_mask must stay at offset 603 (cmd/wdog/file.go)");

/* A credential-switch rule: the task changing its OWN user or group identity,
 * which is what su and sudo do once they are running.
 *
 * There is deliberately no "from" field. The source identity is the audit login
 * uid, and that is already part of the key wax_active_cred_policy_by_uid was
 * looked up by — a from_uid would either restate it or be dead. Read a rule as
 * "the login uid this policy belongs to may not acquire to_uid". The employee
 * half of that key says the same thing about the person: the actor axis is
 * always what selects the policy, never what a rule carries.
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
    __u32 to_uid;                   /* 288 — OP_SETUID only */
    __u32 to_gid;                   /* 292 — OP_SETGID only */
    __u8 has_to_uid;                /* 296 — to_uid is meaningful */
    __u8 has_to_gid;                /* 297 — to_gid is meaningful */
    __u8 op_mask;                   /* 298 — CRED_OP_*_BIT; which ops this covers */
    __u8 enabled;                   /* 299 */
    __u8 deny;                      /* 300 */
    __u8 no_event_s;                /* 301 — CRED_OP_* mask: ops with no 'S' */
    __u8 exec_suffix_len;           /* 302 */
    __u8 warn;                      /* 303 — this rule alone is observe-only */
    __u8 no_event_fw;               /* 304 — CRED_OP_* mask: ops with no 'F'/'W' */
    /* ORIGIN_BIT mask, 0 for "any origin". See struct rule::origin_mask.
     *
     * Read this one twice before writing a rule with it. The login descent is
     * judged here — sshd and crond setuid down to the user AFTER pam_loginuid
     * has given them that user's session — so an origin-scoped deny in credRules
     * locks out exactly the kind of login it names. docs/rules-process.md carries
     * the warning in full. */
    __u8 origin_mask;               /* 305 */
    __u8 _pad[2];                   /* 306 */
};                                  /* 308 */

/* to_uid and to_gid keep the alignment at 4, so the two trailing padding bytes
 * are still the last free ones.
 *
 * ⚠ 308 is a size this struct has HELD BEFORE — it is what it was before
 * no_event_fw cost four bytes and grew it to 312. Read struct rule's note
 * above: the value size no longer identifies a generation, and the outer map's
 * 8-byte key is what does. */
_Static_assert(sizeof(struct cred_rule) == 308, "struct cred_rule must stay 308 bytes");
_Static_assert(__builtin_offsetof(struct cred_rule, warn) == 303,
               "cred_rule.warn must stay at offset 303 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct cred_rule, no_event_fw) == 304,
               "cred_rule.no_event_fw must stay at offset 304 (cmd/wdog/file.go)");
_Static_assert(__builtin_offsetof(struct cred_rule, origin_mask) == 305,
               "cred_rule.origin_mask must stay at offset 305 (cmd/wdog/file.go)");

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
 * open_session and marks it SESSION_CLOSED (not deleted) at close_session; wdog
 * reaps records whose session no longer has a live process. See the origin
 * paragraphs below for why the record lingers.
 *
 * login_uid is not a matching criterion — it exists so a record left behind by
 * a session whose id has since been reused cannot lend its name to a different
 * user.
 *
 * login_time_ns is the wall clock at open_session, CLOCK_REALTIME nanoseconds
 * since the epoch. Nothing in the kernel reads it — it exists so wdog can stamp
 * the audit line with when the session behind an event logged in. Zero means
 * "not recorded": either an older pam_wood.so wrote this record, or the module
 * could not read a clock. wdog then derives an approximation from /proc and
 * never writes it back here; this map is written by PAM alone, and the
 * self-defense layer (door/self_progs.h) is built on that.
 *
 * INVARIANT: employee_name must be zero-padded to its full width, not merely
 * NUL-terminated. It is used as a hash-map key below, and a key is compared as
 * a fixed-size block of bytes — junk after the terminator would look up nothing
 * at all. pam_wood.c memsets the value before filling it for this reason.
 *
 * origin is the third user axis and the only one of the three fields added last
 * that the kernel reads. It took what had been _pad, so login_time_ns did not
 * move. See ORIGIN_* in door/file_const.h for what it is and why it lives on the
 * session rather than on the process.
 *
 * Its LOW BYTE is the origin; the high bits are flags, so far only
 * SESSION_CLOSED. Read it through ORIGIN_VALUE() and never raw. Packing rather
 * than adding a field is deliberate: growing this struct is the deployment
 * hazard written up below, and the spare bits were already paid for.
 *
 * SESSION_CLOSED says close_session has run while processes still carry this
 * session id. The record LINGERS until wdog's reaper sees the last of them go.
 * That covers the case the origin axis was weakest on: a login whose processes
 * outlive it — a remote-IDE server, nohup, tmux, setsid — used to lose both user
 * axes at logout and match only rules that constrain neither.
 *
 * service and rhost are the raw PAM_SERVICE and PAM_RHOST, recorded whatever
 * origin was decided (ORIGIN_UNKNOWN included). NOTHING IN THE KERNEL READS
 * THEM. They exist so an operator reading an audit line sees what the module
 * saw, which turns "why is this session unknown" from a guess into a lookup: a
 * site-local PAM service the built-in table has never heard of shows up by name,
 * and the remedy is an origin= option in that stack. rhost carries what sshd put
 * there and is empty for every local origin. Both are NUL-terminated and
 * zero-padded like employee_name, though neither is a hash key.
 *
 * Their cost is real and worth stating: this value went 80 -> 176 bytes, and at
 * max_entries 65536 the preallocated map went 5.2MB -> 11.5MB. See
 * door/file_maps.h. */
struct session_identity {
    char employee_name[EMPLOYEE_NAME_LEN];  /*   0 */
    __u32 login_uid;                        /*  64 */
    __u32 origin;                           /*  68 — ORIGIN_*, was _pad */
    __u64 login_time_ns;                    /*  72 */
    char service[SESSION_SERVICE_LEN];      /*  80 — PAM_SERVICE, reporting only */
    char rhost[SESSION_RHOST_LEN];          /* 112 — PAM_RHOST, reporting only */
};                                          /* 176 */

/* This value crosses three build systems — this object, door/net.c, and
 * pam/pam.c, which is compiled separately and gets no word from the kernel when
 * it is wrong (BPF_MAP_UPDATE_ELEM copies map->value_size bytes from wherever
 * the module points, whatever the module thinks the size is). The asserts are
 * what catches a mirror drifting; see cmd/wdog/session.go for the fourth.
 *
 * That copy is why growing this struct is a DEPLOYMENT hazard and not merely an
 * ABI one, and the direction that hurts is the counter-intuitive one. A stale
 * 80-byte pam_wood.so writing into a freshly pinned 176-byte map makes the
 * kernel read 96 bytes past the module's stack object and store them where an
 * operator can read them back. The reverse — a new module, an old map — merely
 * fails. So the module and the daemons ship as one unit; see pam/pam.c and the
 * upgrade note in docs/deploy.md. */
_Static_assert(sizeof(struct session_identity) == 176,
               "session_identity is the pinned wax_session_identity value; its size is an "
               "interface with pam/pam.c and cmd/wdog/session.go");
_Static_assert(__builtin_offsetof(struct session_identity, login_time_ns) == 72,
               "session_identity.login_time_ns must stay at offset 72 (pam/pam.c)");
/* origin took _pad, which is exactly why the offset above did not have to move.
 * Pin it: a field inserted ahead of it would keep the size at 176 by taking
 * room from service or rhost and silently repoint the one field here the kernel
 * matches on. */
_Static_assert(__builtin_offsetof(struct session_identity, origin) == 68,
               "session_identity.origin must stay at offset 68 (pam/pam.c)");
_Static_assert(__builtin_offsetof(struct session_identity, service) == 80,
               "session_identity.service must stay at offset 80 (pam/pam.c)");
_Static_assert(__builtin_offsetof(struct session_identity, rhost) == 112,
               "session_identity.rhost must stay at offset 112 (pam/pam.c)");

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
