// SPDX-License-Identifier: GPL-2.0 OR MIT
// Dual-licensed; the kernel-facing license string stays GPL-compatible
// ("Dual MIT/GPL") so gpl_only helpers such as bpf_d_path remain usable.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
/* Employee names are short human identifiers, not paths; 64 bytes leaves room
 * for a 63-character name plus its NUL. Rules do not store the name — see
 * struct rule::employee_id — but the session record and the intern table do. */
#define EMPLOYEE_NAME_LEN 64
/* A rule that constrains no employee, and the id of a session whose employee
 * is unknown. The two meeting is what makes an unidentified session match only
 * the rules that name nobody. */
#define EMPLOYEE_ID_ANY 0
/* Converts start_boottime to the units /proc/<pid>/stat reports. USER_HZ is 100
 * in the kernel's /proc ABI regardless of CONFIG_HZ, and fs/proc/array.c derives
 * starttime from the same start_boottime, so dividing here reproduces that field
 * exactly rather than approximately — which is what lets wdog prime pid_image
 * from /proc and have the entries pass their own staleness check. */
#define NSEC_PER_CLOCK 10000000ULL
/* Policy IDs are typically 32-character strings; 39 bytes + NUL also covers
 * dashed UUIDs, and 40 keeps the fields after it naturally aligned. */
#define POLICY_ID_LEN 40
#define MAX_RULES 512
#define OP_EXEC    1
#define OP_READ    2
#define OP_WRITE   3
/* Operations below are write-class: they are governed by the write rules. */
#define OP_UNLINK  4
#define OP_RENAME  5
#define OP_CHMOD   6
#define OP_CHOWN   7
#define OP_SETTIME 8
#define OP_MKDIR   9
#define OP_SYMLINK 10
#define OP_LINK    11
#define OP_MKNOD   12
#define OP_TRUNCATE 13
/* Operations on another process. Governed by proc_rule rather than rule: what
 * they act on is a task, not a path, so they need their own set of constraints.
 * The two share one rule array; a rule says which of them it covers in
 * proc_rule::op_mask. */
#define OP_KILL    14
#define OP_PTRACE  15
/* A task changing its OWN credentials. Governed by cred_rule: there is no
 * second process and no path, only the identity being acquired. 16-19 are the
 * gap between the process controls and the network codes in net.c. */
#define OP_SETUID  16
#define OP_SETGID  17

/* cred_rule::op_mask bits, the same kind of set proc_rule carries: one rule
 * covers the user switch, the group switch, or both. */
#define CRED_OP_SETUID_BIT 0x01
#define CRED_OP_SETGID_BIT 0x02

/* include/linux/security.h; the flags argument of task_fix_setuid/setgid says
 * which syscall family made the change. Reported on the event, never matched —
 * glibc's seteuid() lowers to setresuid(), so a rule distinguishing them would
 * not do what its author expected. */
#define LSM_SETID_ID  1
#define LSM_SETID_RE  2
#define LSM_SETID_RES 4
#define LSM_SETID_FS  8

/* proc_rule::op_mask bits. Separate from the OP_ codes above because those name
 * the one operation being judged, while a rule carries a set: writing the
 * target axis once and having it cover both signals and debugging is the usual
 * case, since a debugger that can attach to a process can drive it wherever it
 * likes — strictly more than killing it. */
#define PROC_OP_KILL_BIT   0x01
#define PROC_OP_PTRACE_BIT 0x02

/* ptrace access modes, from include/linux/ptrace.h. The mode argument also
 * carries FSCREDS/REALCREDS/NOAUDIT flags, so it is masked down to these two
 * before matching. ATTACH is debugging proper; READ additionally covers
 * /proc/<pid>/mem and environ, process_vm_readv() and kcmp(). */
#define PTRACE_MODE_READ_BIT   0x01
#define PTRACE_MODE_ATTACH_BIT 0x02
#define PTRACE_MODE_MASK       0x03
#define FMODE_READ  0x00000001
#define FMODE_WRITE 0x00000002
/* include/linux/fs.h iattr ia_valid flags */
#define ATTR_SIZE      (1 << 3)
#define ATTR_MTIME     (1 << 5)
#define ATTR_MTIME_SET (1 << 8)
#define MAX_DENTRY_DEPTH 48
#define MAX_CGROUP_DEPTH 32
#define MODE_ENFORCE 0
#define MODE_WARN    1
/* Permission bits selecting which operations a rule governs. */
#define PERM_EXEC  1
#define PERM_READ  2
#define PERM_WRITE 4

/* A rule matches when the current process image matches exec_path, the target
 * matches path, and the operation's permission bit is set. Patterns are stored
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
 * RHEL 9 (5.14), it put check_net_sendmsg in net.c past the one-million
 * instruction ceiling and the object stopped loading. A scalar compare costs
 * nothing. The loader interns each distinct name to an id and publishes the
 * mapping in employee_ids, which check_policy consults once per check —
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
    __u8 no_event;
    __u8 exec_suffix_len;
    __u8 path_suffix_len;
    __u8 _pad[2];
};

/* The userspace loader writes this by byte offset (cmd/wdog/file.go) and
 * file_test.go pins the size, so a silent layout change here would apply policy
 * to the wrong fields rather than fail to build. */
_Static_assert(sizeof(struct rule) == 588, "struct rule must stay 588 bytes");

/* A signal rule. Deliberately not struct rule: the thing being acted on is
 * another process, so the constraints describe a task rather than a path.
 *
 * exec_path is the SENDER's image and target_path the TARGET's, both matched
 * with the same glob syntax and matcher the file rules use. Neither can come
 * from bpf_d_path here — the helper is rejected at this attach point on RHEL 9
 * (measured: "helper call is not allowed") — so both are read out of pid_image,
 * which the exec hook fills while d_path is still available. That indirection
 * is the whole reason pid_image exists.
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
    __u8 no_event;                  /* 599 */
    __u8 exec_suffix_len;           /* 600 */
    __u8 target_suffix_len;         /* 601 */
    __u8 op_mask;                   /* 602 — PROC_OP_*_BIT; which ops this covers */
    __u8 ptrace_mode;               /* 603 — OP_PTRACE only; 0 = any mode */
    __u8 _pad[4];                   /* 604 */
};                                  /* 608 */

/* The two bytes came out of the tail padding, so the process controls did not
 * move a single field of the file rule they were modelled on. */
_Static_assert(sizeof(struct proc_rule) == 608, "struct proc_rule must stay 608 bytes");

/* A credential-switch rule: the task changing its OWN user or group identity,
 * which is what su and sudo do once they are running.
 *
 * There is deliberately no "from" field. The source identity is the audit login
 * uid, and that is already the key active_cred_policy_by_uid was looked up by —
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
 * pid_image, filled on exec where the helper is allowed. */
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
    __u8 no_event;                  /* 305 */
    __u8 exec_suffix_len;           /* 306 */
    __u8 _pad[1];                   /* 307 */
};                                  /* 308 */

_Static_assert(sizeof(struct cred_rule) == 308, "struct cred_rule must stay 308 bytes");

struct policy_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN]; /* NUL-terminated policy id */
};

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
 * session_identity. */
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
};

/* zero_event clears the record eight bytes at a time and bpf_ringbuf_reserve is
 * given sizeof(), so the total must stay a multiple of 8. The Go side reads
 * only the declared 1436 and file_test.go pins the offsets. */
_Static_assert(sizeof(struct event) == 1440, "struct event must stay 1440 bytes");

struct pending_exec_event {
    __u32 uid;
    __u8 status;
    __u8 _pad[3];
    char file[PATH_LEN];
    char executable_path[PATH_LEN];
    char policy_id[POLICY_ID_LEN];
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
 * (inode_setattr). Same 2x headroom rationale as file_path_scratch. */
struct dentry_walk_scratch {
    char build[PATH_LEN * 2];
    char name[PATH_LEN];
};

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct policy_slot);
} policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(policy_template));
} active_policy_by_uid SEC(".maps");

/* Signal rules get their own array and their own map-in-map rather than
 * sharing the file rules': the slot layouts differ, and keeping the two apart
 * means neither loop walks past rules it can never match. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct proc_policy_slot);
} proc_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(proc_policy_template));
} active_proc_policy_by_uid SEC(".maps");

/* Credential rules get a third array for the same reason the signal rules got a
 * second one: the slot is a different size, and a setuid check has no business
 * walking rules that can only ever match a signal. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct cred_policy_slot);
} cred_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(cred_policy_template));
} active_cred_policy_by_uid SEC(".maps");

/* tgid -> the image that process is running.
 *
 * Written on exec (where bpf_d_path works), inherited on fork (a process that
 * forks without exec keeps its parent's image), and dropped on exit. wdog
 * primes it from /proc at startup, which is what covers the daemons that were
 * already running — and those are precisely the processes a kill rule is
 * usually written to protect.
 *
 * LRU rather than a plain hash: unlike session_identity there is no external
 * writer to report an overflow, and losing an entry degrades to "image
 * unknown" rather than to a wrong answer. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); /* tgid */
    __type(value, struct pid_image);
} pid_image SEC(".maps");

/* Staging for pid_image, exactly mirroring pending_execs' reason for existing:
 * bprm_check_security runs BEFORE the exec is committed, and the exec can still
 * fail afterwards. Recording the image straight from there would let a process
 * claim an image it never actually ran. The sched_process_exec tracepoint
 * promotes the entry once the new image is live. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pid_image);
} pending_image SEC(".maps");

/* struct pid_image is 272 bytes — more than half the verifier's 512-byte call
 * stack, and the exec hook that fills one also calls check(). Assembled here
 * instead, like every other oversized record in this file. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pid_image);
} pending_image_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_config);
} runtime_config_map SEC(".maps");

/* Audit session id -> the employee PAM logged in on it. Written from userspace
 * only (pam_wood.so on login/logout, wdog's reaper for sessions that died
 * without a close_session), read here on every check.
 *
 * Pinned, and declared identically in net.c, because the two BPF objects cannot
 * share a map any other way: LIBBPF_PIN_BY_NAME makes whichever object loads
 * second attach to the map the first one created. The pin also outlives wdog,
 * so a restart does not lose the identities of sessions already logged in.
 *
 * A plain hash rather than an LRU on purpose: evicting a live session's record
 * would silently stop its name-scoped deny rules from matching. Overflow is
 * reported by PAM instead, and the reaper keeps the table from filling with
 * sessions that are already gone. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* audit session id */
    __type(value, struct session_identity);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} session_identity SEC(".maps");

/* Employee name -> the id rules carry, interned by the loader. Written only by
 * wdog, and only while installing policies; read here once per check.
 *
 * Ids are assigned in order of first appearance and never reused for as long as
 * wdog runs, so a policy replacement cannot silently repoint an id that rules
 * from the previous generation still reference.
 *
 * Pinned and shared exactly like session_identity, and for the same reason: the
 * file and network objects have to agree on the id space. */
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
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} pending_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} pending_exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct executable_path_scratch);
} executable_path_scratch SEC(".maps");

/* bpf_d_path output is kept off the BPF call stack. check() invokes policy
 * callbacks and path matchers, so a 256-byte local buffer would exceed the
 * verifier's 512-byte combined call-stack limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_path_scratch);
} file_path_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dentry_walk_scratch);
} dentry_walk_scratch_map SEC(".maps");

/*
 * Verifier-friendly glob matcher. Pattern bytes are stored unescaped; the wild
 * bitmap marks which positions are wildcards: '?' matches one non-NUL byte and
 * '*' is supported as a terminal wildcard (for example, "/usr/bin/" plus '*').
 * A '*' or '?' byte without its wild bit set matches only the literal byte.
 * Keeping the character scan in bpf_loop's callback prevents it from
 * multiplying the states of the outer policy loop on older 5.14-based
 * verifiers.
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

/* Suffix matcher for patterns that lead with a wildcard '*'. The wildcard's
 * span is fixed rather than searched — the loader supplies the suffix length,
 * so the comparison simply starts at path_len - suffix_len and walks forward,
 * keeping this the same single scan as the prefix case. Pattern index i + 1
 * skips the leading '*'; ctx->start is bounded by the caller so every path
 * index stays inside PATH_LEN. */
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

/* A leading NUL with its wild bit clear is the "always matches any path"
 * pattern. Patterns must be NUL-terminated within PATH_LEN by the loader; a
 * pattern that fills all PATH_LEN bytes without a NUL never sets matched below,
 * so it safely fails to match rather than reading past the buffer. */
static __always_inline int pattern_is_empty(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '\0' && !(wild[0] & 1);
}

/* A wildcard '*' in position 0 anchors the pattern to the path's tail. An
 * escaped literal '*' has its wild bit clear and is not a suffix pattern. */
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
        /* Paths that did not fit PATH_LEN were truncated, so their real tail
         * is not observable here and a suffix rule must not claim a match. */
        if (path_len >= PATH_LEN) return 0;
        if (suffix_len > path_len) return 0;
        ctx.start = path_len - suffix_len;
        bpf_loop(PATH_LEN, match_suffix_cb, &ctx, 0);
        return ctx.matched;
    }
    bpf_loop(PATH_LEN, match_path_cb, &ctx, 0);
    return ctx.matched;
}

/* Resolve this task's audit session to the employee id its rules are written
 * against: session -> name (what PAM recorded) -> id (what the loader interned).
 *
 * EMPLOYEE_ID_ANY comes back whenever that chain breaks, and every break is an
 * ordinary state rather than a failure: no PAM module installed, no name
 * configured for the login, or a name no rule mentions. Since a rule scoped to
 * an employee carries a non-zero id, such a session matches only the rules that
 * name nobody — deny rules included. Failing closed instead would deny every
 * unidentified session everything any name-scoped deny rule mentions, which is
 * most of the machine. "Deny whoever is not identified" is written as a
 * trailing catch-all deny rule naming no employee, which first-match-wins
 * reaches once the per-person rules above it have missed.
 *
 * Called once per check, before the rule loop. That placement is deliberate:
 * everything here branches on pointers, and doing any of it per rule is what
 * exhausts the verifier — see struct rule::employee_id. */
static __always_inline __u32 current_employee_id(struct task_struct *task,
                                                 __u32 login_uid)
{
    __u32 sid = BPF_CORE_READ(task, sessionid);
    struct session_identity *si;
    __u32 *id;

    if (sid == (__u32)-1) return EMPLOYEE_ID_ANY;
    si = bpf_map_lookup_elem(&session_identity, &sid);
    if (!si) return EMPLOYEE_ID_ANY;
    /* Audit session ids are reused after a reboot, and a session killed hard
     * never runs close_session. A record whose login uid no longer matches is
     * one of those leftovers and must not lend its name to this task. */
    if (si->login_uid != login_uid) return EMPLOYEE_ID_ANY;
    /* The name is looked up in place: employee_name_key is exactly the leading
     * field of the record, so no copy to a key buffer is needed. */
    id = bpf_map_lookup_elem(&employee_ids, si->employee_name);
    if (!id) return EMPLOYEE_ID_ANY;
    return *id;
}

/* The same resolution for a task that is not the current one — the target of a
 * signal. Kept separate rather than parameterising current_employee_id because
 * the login uid has to come from the task itself here, not from the policy
 * lookup that already resolved it for the caller. */
static __always_inline __u32 target_employee_id(struct task_struct *task)
{
    return current_employee_id(task, BPF_CORE_READ(task, loginuid.val));
}

/* Rebuild the cgroup v2 path right-to-left over the kernfs parent chain,
 * mirroring the dentry walk below. Reuses dentry_walk_scratch: by the time an
 * event is emitted every hook has already copied its walked path into
 * file_path_scratch, so the buffer is idle. */
struct cgroup_walk_ctx {
    struct kernfs_node *kn;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

/*
 * RHEL 9.8 (kernel 5.14.0-687) backported the upstream rename of
 * kernfs_node::parent to kernfs_node::__parent (the RCU conversion). The
 * build-time vmlinux.h only carries one of the two names, so read whichever the
 * running kernel actually exposes. bpf_core_field_exists() folds the unused
 * branch to a constant the verifier prunes, so the CO-RE relocation for the
 * field that is absent on the target never sits on a live code path.
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

static __always_inline void fill_cgroup(struct event *e, struct task_struct *task)
{
    __u32 zero = 0;
    struct kernfs_node *kn;
    struct dentry_walk_scratch *s;
    struct cgroup_walk_ctx ctx;

    e->cgroup_id = bpf_get_current_cgroup_id();
    kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn) return;
    s = bpf_map_lookup_elem(&dentry_walk_scratch_map, &zero);
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
 * unrolled word loop. sizeof(struct event) is a multiple of 8 (u64 members
 * force 8-byte alignment), and ring-buffer memory is 8-byte aligned. */
static __always_inline void zero_event(struct event *e)
{
    /* volatile stores keep clang from re-coalescing the unrolled loop back
     * into an (unsupported) memset call. */
    volatile __u64 *p = (volatile __u64 *)e;

#pragma unroll
    for (int i = 0; i < sizeof(*e) / 8; i++)
        p[i] = 0;
}

/* The credential hooks' share of the event, passed by pointer so the other
 * three emit_event call sites stay as they were. NULL means "not a credential
 * event" and leaves the three fields zero. */
struct cred_event_ids {
    __u32 from_id;
    __u32 to_id;
    __u8 flags;
};

static __always_inline void emit_event(__u32 uid, __u8 op, __u8 status,
                                       const char *path, const char *executable_path,
                                       const char *policy_id, __u8 capture_cmdline,
                                       __u8 signal, const struct cred_event_ids *ids)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    struct task_struct *task;
    struct tty_struct *tty = 0;
    struct mm_struct *mm = 0;
    unsigned long arg_start = 0, arg_end = 0;
    __u32 cmdline_len = 0;
    if (!e) return;
    /* Zero the whole record up front so the fixed-size string fields and the
     * trailing struct padding never carry stale ring-buffer bytes (from prior
     * events) past their NUL terminators into userspace. */
    zero_event(e);
    e->uid = uid;
    e->real_uid = (__u32)bpf_get_current_uid_gid();
    e->operation = op;
    e->status = status;
    e->signal = signal;
    if (ids) {
        e->from_id = ids->from_id;
        e->to_id = ids->to_id;
        e->setid_flags = ids->flags;
    }
    e->create_timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
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
    if (capture_cmdline && mm) {
        BPF_CORE_READ_INTO(&arg_start, mm, arg_start);
        BPF_CORE_READ_INTO(&arg_end, mm, arg_end);
        if (arg_end > arg_start) {
            unsigned long arg_len = arg_end - arg_start;
            cmdline_len = arg_len > CMDLINE_LEN ? CMDLINE_LEN : (__u32)arg_len;
            if (bpf_probe_read_user(e->cmdline, cmdline_len, (void *)arg_start) == 0)
                e->cmdline_len = cmdline_len;
        }
    }
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
    if (executable_path)
        bpf_probe_read_kernel_str(e->executable_path,
                                  sizeof(e->executable_path), executable_path);
    if (policy_id)
        bpf_probe_read_kernel_str(e->policy_id, sizeof(e->policy_id), policy_id);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void queue_exec_event(__u32 uid, __u8 status, const char *path,
                                             const char *policy_id)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 zero = 0;
    struct pending_exec_event *pending;
    struct executable_path_scratch *scratch;
    struct task_struct *task;
    struct task_struct *parent;
    struct mm_struct *parent_mm;
    struct file *exe_file;

    pending = bpf_map_lookup_elem(&pending_exec_scratch, &zero);
    if (!pending) return;
    pending->uid = uid;
    pending->status = status;
    bpf_probe_read_kernel_str(pending->file, sizeof(pending->file), path);
    pending->executable_path[0] = '\0';
    pending->policy_id[0] = '\0';
    if (policy_id)
        bpf_probe_read_kernel_str(pending->policy_id, sizeof(pending->policy_id),
                                  policy_id);
    scratch = bpf_map_lookup_elem(&executable_path_scratch, &zero);
    if (scratch) {
        scratch->path[0] = '\0';
        task = (struct task_struct *)bpf_get_current_task_btf();
        /* Keep these as typed pointer dereferences so exe_file stays a trusted
         * PTR_TO_BTF_ID for bpf_d_path; BPF_CORE_READ would downgrade it to a
         * scalar and the call would be rejected. Matches check_policy(). */
        parent = task->real_parent;
        if (parent) {
            parent_mm = parent->mm;
            exe_file = parent_mm ? parent_mm->exe_file : 0;
            if (exe_file)
                bpf_d_path(&exe_file->f_path, scratch->path,
                           sizeof(scratch->path));
        }
        bpf_probe_read_kernel_str(pending->executable_path,
                                  sizeof(pending->executable_path), scratch->path);
    }
    bpf_map_update_elem(&pending_execs, &pid, pending, BPF_ANY);
}

struct policy_check_ctx {
    void *inner;
    const char *path;
    const char *executable_path;
    const char *policy_id;
    /* The caller's interned employee id, EMPLOYEE_ID_ANY when unknown.
     * Resolved once per check rather than per rule; see current_employee_id. */
    __u32 employee_id;
    __u32 uid;
    __u32 count;
    /* strlen of the two paths, for suffix matching. A value >= PATH_LEN means
     * the path did not fit the buffer and was truncated. */
    __u32 path_len;
    __u32 exec_path_len;
    __u8 op;
    __u8 perm_bit;
    __u8 matched;
    __u8 exec_resolved; /* current process image was resolved via bpf_d_path */
    int result;
};

/*
 * Keep rule traversal inside bpf_loop rather than a C-bounded loop.  Larger
 * policy limits would otherwise be unrolled by clang and exceed the verifier's
 * instruction limit before the program can load.
 */
static long check_rule_cb(__u32 i, void *data)
{
    struct policy_check_ctx *ctx = data;
    __u32 zero = 0, index;
    struct policy_slot *slot;
    struct rule *r;
    struct runtime_config *cfg;
    __u8 denied, status;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;
    if (!(r->permission & ctx->perm_bit)) return 0;
    /* Scalars only, on purpose: see struct rule::employee_id. An unidentified
     * caller has EMPLOYEE_ID_ANY, so a rule scoped to anyone cannot match it. */
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
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
             * cannot shadow a later deny. The path test below still applies. */
            if (!r->deny) return 0;
        }
    }
    if (!match_path_pattern(r->path, r->path_wild, r->path_suffix_len, ctx->path,
                            ctx->path_len))
        return 0;

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    if (!r->no_event) {
        if (ctx->op == OP_EXEC && !denied)
            queue_exec_event(ctx->uid, status, ctx->path, ctx->policy_id);
        else
            emit_event(ctx->uid, ctx->op, status, ctx->path, ctx->executable_path,
                       ctx->policy_id, ctx->op != OP_EXEC, 0, 0);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;
}

static __always_inline int task_is_exempt(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, sessionid) == (__u32)-1;
}

/* Evaluate an already-resolved path against the caller's policy. Policies
 * are selected — and events attributed — by the audit login uid, which
 * pam_loginuid assigns at login and survives su/sudo, so a user stays under
 * their own policy after switching to root. The operation selects the
 * permission bit rules must carry: exec(1), read(2), or write(4) for every
 * write-class operation (write, truncate, unlink, rename, chmod, chown,
 * settime, mkdir, symlink, link, mknod). The first rule whose permission bit,
 * employee_id, exec_path pattern (current process image) and path pattern all
 * match decides the outcome.
 *
 * The employee is the second user axis: the login uid picks the policy, the
 * employee picks which of its rules apply. That is what makes a shared account —
 * one uid, many people — controllable per person. */
static __always_inline int check_policy(const char *path, __u32 path_len, __u8 op)
{
    __u32 uid, zero = 0, count, exec_path_len = 0;
    struct task_struct *task;
    struct policy_slot *meta;
    struct policy_check_ctx ctx;
    struct executable_path_scratch *executable_scratch;
    struct mm_struct *mm;
    struct file *exe_file;
    void *inner;
    const char *executable_path = 0;
    __u8 exec_resolved = 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&active_policy_by_uid, &uid);
    if (!inner) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0);
        return 0;
    }
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0);
        return 0;
    }
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, meta->meta.id);
        return 0;
    }
    /* Resolve the current process image for exec_path matching. For OP_EXEC
     * this is still the invoking image (e.g. the shell): bprm_check runs
     * before the new image is committed. */
    executable_scratch = bpf_map_lookup_elem(&executable_path_scratch, &zero);
    if (executable_scratch) {
        executable_scratch->path[0] = '\0';
        executable_path = executable_scratch->path;
        /* Keep these as typed pointer dereferences. bpf_d_path requires a
         * trusted PTR_TO_BTF_ID; BPF_CORE_READ would turn exe_file into a
         * scalar from the verifier's perspective. */
        mm = task->mm;
        exe_file = mm ? mm->exe_file : 0;
        if (exe_file) {
            long n = bpf_d_path(&exe_file->f_path, executable_scratch->path,
                                sizeof(executable_scratch->path));

            if (n > 0) {
                exec_resolved = 1;
                exec_path_len = (__u32)n - 1;   /* n counts the NUL */
            }
        }
    }

    ctx = (struct policy_check_ctx){
        .inner = inner,
        .path = path,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        /* Two hash lookups per check, next to the bpf_d_path above that costs
         * considerably more. Policies with no name-scoped rules still pay them,
         * but never consult the result. */
        .employee_id = current_employee_id(task, uid),
        .uid = uid,
        .count = count,
        .path_len = path_len,
        .exec_path_len = exec_path_len,
        .op = op,
        .perm_bit = op == OP_EXEC ? PERM_EXEC :
                    op == OP_READ ? PERM_READ : PERM_WRITE,
        .exec_resolved = exec_resolved,
    };
    bpf_loop(MAX_RULES, check_rule_cb, &ctx, 0);
    /* A configured policy still audits allowed executables that did not match
     * any rule.  Allowed matching rules have already queued their own event
     * in check_rule_cb. */
    if (op == OP_EXEC && !ctx.matched)
        queue_exec_event(uid, 'S', path, meta->meta.id);
    return ctx.result;
}

static __always_inline int check(struct file *file, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *path_scratch;
    long len;

    if (task_is_exempt()) {
        /* Do not retain an older pending exec event for an exempt task. */
        if (op == OP_EXEC) {
            __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            bpf_map_delete_elem(&pending_execs, &pid);
        }
        return 0;
    }
    path_scratch = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!path_scratch) return 0;
    path_scratch->path[0] = '\0';
    len = bpf_d_path(&file->f_path, path_scratch->path, PATH_LEN);
    if (len <= 0) return 0;
    if (op == OP_EXEC) {
        __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        bpf_map_delete_elem(&pending_execs, &pid);
    }
    return check_policy(path_scratch->path, (__u32)len - 1, op);
}

/* Resolve "parent directory path" + "/" + "dentry name" into the shared path
 * scratch and run the write-class policy on it. Used by
 * unlink/rmdir/mkdir/symlink/link/mknod/rename,
 * whose hooks receive the target as a (parent path, dentry) pair. */
static __always_inline int check_dir_dentry(const struct path *dir,
                                            struct dentry *dentry, __u8 op)
{
    __u32 zero = 0, off;
    struct file_path_scratch *ps;
    const unsigned char *name;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)dir, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    off = (__u32)len - 1;                       /* index of the NUL */
    if (off >= PATH_LEN) return 0;
    /* barrier_var keeps clang from re-deriving these offsets from len, which
     * would drop the masks the verifier needs to see. */
    barrier_var(off);
    off &= PATH_LEN - 1;
    if (off > 0) {
        __u32 prev = off - 1;

        barrier_var(prev);
        prev &= PATH_LEN - 1;
        if (ps->path[prev] == '/') off = prev;  /* parent is "/" */
    }
    ps->path[off] = '/';
    name = BPF_CORE_READ(dentry, d_name.name);
    len = bpf_probe_read_kernel_str(&ps->path[off + 1], PATH_LEN, name);
    if (len <= 0) return 0;
    /* off + 1 leading bytes plus len - 1 component bytes. This is the one
     * producer that can exceed PATH_LEN, which only suffix rules care about;
     * they decline to match a path they cannot see the end of. */
    return check_policy(ps->path, off + (__u32)len, op);
}

/* Hooks that receive the target as a struct path resolve it directly. */
static __always_inline int check_path_op(const struct path *p, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *ps;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)p, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * inode_setattr only receives a dentry, so the path is rebuilt by walking
 * d_parent toward the filesystem root, writing components right-to-left.
 * The result lacks the mount prefix for files on non-root mounts; rules are
 * matched against the path as seen from that filesystem's root.
 */
struct dentry_walk_ctx {
    struct dentry *d;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

static long dentry_walk_cb(__u32 i, void *data)
{
    struct dentry_walk_ctx *ctx = data;
    struct dentry *d = ctx->d, *parent;
    const unsigned char *name;
    __u32 pos, sz;
    long len;

    if (!d) {
        ctx->failed = 1;
        return 1;
    }
    parent = BPF_CORE_READ(d, d_parent);
    if (parent == d) {
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(d, d_name.name);
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
    ctx->d = parent;
    return 0;
}

static __always_inline int check_dentry_op(struct dentry *dentry, __u8 op)
{
    __u32 zero = 0;
    struct dentry_walk_scratch *s;
    struct file_path_scratch *ps;
    struct dentry_walk_ctx ctx;
    long len;

    if (task_is_exempt()) return 0;
    s = bpf_map_lookup_elem(&dentry_walk_scratch_map, &zero);
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!s || !ps) return 0;
    s->build[PATH_LEN] = '\0';
    ctx = (struct dentry_walk_ctx){ .d = dentry, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_DENTRY_DEPTH, dentry_walk_cb, &ctx, 0);
    /* Allow rather than mis-match on an incomplete (too deep/long) walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return 0;
    if (ctx.pos == PATH_LEN) {                  /* dentry was the root itself */
        ps->path[0] = '/';
        ps->path[1] = '\0';
        len = 2;
    } else if ((len = bpf_probe_read_kernel_str(ps->path, PATH_LEN,
                                                &s->build[ctx.pos])) <= 0) {
        return 0;
    }
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * Strict LSM verifiers (e.g. RHEL 9.8, kernel 5.14.0-687) require every hook to
 * return a value provably within [-4095, 0]. Two things are needed. First, the
 * hooks return `long` so clang sign-extends the result into the full 64-bit R0:
 * an `int` return emits a 32-bit move that zero-extends, turning a negative
 * errno (e.g. -EACCES) into a large positive value the verifier rejects.
 * Second, lsm_ret() clamps the value with signed comparisons so the verifier
 * can bound smin/smax to exactly [-4095, 0]. Valid results (0, -EACCES, or a
 * prior hook's errno) pass through unchanged. Older 5.14 verifiers (RHEL 9.5)
 * accepted the un-clamped `int` form, so this only tightens portability.
 */
static __always_inline long lsm_ret(long r)
{
    /* barrier_var keeps clang from proving the value's range at compile time
     * (e.g. that check() only yields 0 or -EACCES) and then dropping a clamp or
     * lowering it to a 32-bit subregister compare the verifier cannot tie back
     * to the returned register. Forcing an opaque 64-bit value before each
     * signed compare makes the verifier track smin/smax on the exact register
     * that is returned. */
    barrier_var(r);
    if (r < -4095)
        r = -4095;
    barrier_var(r);
    if (r > 0)
        r = 0;
    barrier_var(r);
    return r;
}

/* ---------------------------------------------------------------------------
 * Signal control.
 *
 * The sender is judged the same way every other operation is — the login uid
 * picks the policy, the employee narrows the rules. What is new is the TARGET
 * axis: another task, described by its image, its employee and its uid.
 *
 * Neither image can be resolved here. bpf_d_path is rejected at this attach
 * point on RHEL 9, so both come out of pid_image, filled on exec where the
 * helper is allowed. An image that is not in the map reads as unknown, and a
 * rule that constrains that side cannot match — the same fail-to-not-match rule
 * the employee axis uses, and for the same reason: a process wdog never saw
 * exec is an ordinary state, not an attack.
 * ------------------------------------------------------------------------- */

/* The image of a process, or NULL when it is not known. start_clock rejects an
 * entry left behind by a process whose pid has since been reused. */
static __always_inline struct pid_image *task_image(struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    struct pid_image *img = bpf_map_lookup_elem(&pid_image, &tgid);

    if (!img) return 0;
    if (img->start_clock != BPF_CORE_READ(task, start_boottime) / NSEC_PER_CLOCK)
        return 0;
    return img;
}

struct proc_check_ctx {
    void *inner;
    const char *policy_id;
    const char *exec_path;      /* sender's image, or NULL */
    const char *target_path;    /* target's image, or NULL */
    __u32 exec_path_len;
    __u32 target_path_len;
    __u32 uid;
    __u32 employee_id;
    __u32 target_employee_id;
    __u32 target_uid;
    __u32 count;
    __u32 sig;                  /* OP_KILL: the signal number */
    __u8 op;                    /* OP_KILL or OP_PTRACE; what the event reports */
    __u8 op_bit;                /* the same, as the PROC_OP_*_BIT a rule matches on */
    __u8 ptrace_mode;           /* OP_PTRACE: masked to PTRACE_MODE_MASK */
    __u8 matched;
    int result;
};

static long check_proc_rule_cb(__u32 i, void *data)
{
    struct proc_check_ctx *ctx = data;
    __u32 zero = 0, index;
    struct proc_policy_slot *slot;
    struct proc_rule *r;
    struct runtime_config *cfg;
    __u8 denied, status;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;

    /* One array holds the rules for both operations, so the first thing to do
     * is skip the ones that do not cover this one. A rule may cover both, and
     * then it is read by both hooks at its one position in the list — which is
     * what lets a single rule protect a target from signals and debugging
     * alike, and what keeps first-match-wins meaningful for each operation
     * independently. */
    if (!(r->op_mask & ctx->op_bit)) return 0;

    /* Cheapest first, exactly as the network rules order theirs: scalars
     * before the two pattern scans. */
    /* sig > 63 cannot be represented in the mask — Linux's SIGRTMAX is 64 and
     * bit 0 is already signal 0. Masking it down would alias SIGRTMAX onto the
     * kill(pid, 0) bit, so a rule that names any signal simply does not match
     * it; the loader rejects 64 in a rule for the same reason. */
    if (ctx->op == OP_KILL) {
        if (r->signals && (ctx->sig > 63 || !(r->signals & (1ULL << ctx->sig))))
            return 0;
    } else if (r->ptrace_mode && !(r->ptrace_mode & ctx->ptrace_mode)) {
        return 0;
    }
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;
    if (r->target_employee_id != EMPLOYEE_ID_ANY &&
        r->target_employee_id != ctx->target_employee_id)
        return 0;
    if (r->has_target_uid && r->target_uid != ctx->target_uid) return 0;

    if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
        if (!ctx->exec_path) return 0;
        if (!match_path_pattern(r->exec_path, r->exec_wild, r->exec_suffix_len,
                                ctx->exec_path, ctx->exec_path_len))
            return 0;
    }
    if (!pattern_is_empty(r->target_path, r->target_wild)) {
        if (!ctx->target_path) return 0;
        if (!match_path_pattern(r->target_path, r->target_wild,
                                r->target_suffix_len, ctx->target_path,
                                ctx->target_path_len))
            return 0;
    }

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    if (!r->no_event)
        emit_event(ctx->uid, ctx->op, status, ctx->target_path ? ctx->target_path : "",
                   ctx->exec_path, ctx->policy_id, 1,
                   ctx->op == OP_KILL ? (__u8)ctx->sig : ctx->ptrace_mode, 0);
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

/* Split out of the SEC() program because BPF_PROG names its own parameter
 * `ctx`, which would shadow the check context — the same reason every other
 * hook in this file is a thin wrapper over a check_* helper. */
static __always_inline int check_proc_policy(struct task_struct *p, __u8 op,
                                             __u8 op_bit, __u32 sig,
                                             __u8 ptrace_mode)
{
    __u32 uid, zero = 0, count;
    struct task_struct *task;
    struct proc_policy_slot *meta;
    struct proc_check_ctx ctx;
    struct pid_image *self_img, *target_img;
    void *inner;

    if (task_is_exempt()) return 0;
    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&active_proc_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    self_img = task_image(task);
    target_img = task_image(p);
    ctx = (struct proc_check_ctx){
        .inner = inner,
        .policy_id = meta->meta.id,
        .exec_path = self_img ? self_img->exe_path : 0,
        .target_path = target_img ? target_img->exe_path : 0,
        .exec_path_len = self_img ? self_img->path_len : 0,
        .target_path_len = target_img ? target_img->path_len : 0,
        .uid = uid,
        .employee_id = current_employee_id(task, uid),
        .target_employee_id = target_employee_id(p),
        .target_uid = BPF_CORE_READ(p, cred, uid.val),
        .count = count,
        .sig = sig,
        .op = op,
        .op_bit = op_bit,
        .ptrace_mode = ptrace_mode,
    };
    bpf_loop(MAX_RULES, check_proc_rule_cb, &ctx, 0);
    return ctx.result;
}

SEC("lsm/task_kill")
long BPF_PROG(check_task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    return lsm_ret(check_proc_policy(p, OP_KILL, PROC_OP_KILL_BIT, (__u32)sig, 0));
}

/*
 * Debugging access. Worth controlling alongside signals rather than instead of
 * them: stopping someone from killing a process while leaving them able to
 * attach to it protects very little, since a debugger can read its memory and
 * drive it wherever it likes.
 *
 * This hook is not only ptrace(2). The kernel routes every "may I inspect that
 * task" question through it, so a READ-mode rule also governs /proc/<pid>/mem
 * and /proc/<pid>/environ, process_vm_readv() and kcmp(). That reach is the
 * point — reading another process's environ is how credentials leak — but it
 * does mean a broad deny here stops more than a debugger.
 *
 * Access to one's own thread group returns before the hook is reached, so
 * nothing here can stop a process from inspecting itself.
 *
 * PTRACE_TRACEME has its own hook and is deliberately not covered: it is a
 * process asking its OWN parent to trace it, so it cannot be turned into a way
 * to reach a task these rules protect.
 */
SEC("lsm/ptrace_access_check")
long BPF_PROG(check_ptrace_access, struct task_struct *child, unsigned int mode)
{
    /* mode also carries FSCREDS/REALCREDS/NOAUDIT; only the two access bits
     * are matched, and a mode outside them matches only unconstrained rules. */
    return lsm_ret(check_proc_policy(child, OP_PTRACE, PROC_OP_PTRACE_BIT, 0,
                                     (__u8)(mode & PTRACE_MODE_MASK)));
}

/* -------------------------------------------------------------------------
 * Credential switching — setuid/setgid, and so su and sudo.
 *
 * The identity a task is switching TO is the thing an exec rule cannot see:
 * `sudo -u root` and `sudo -u oracle` are the same execve. That is what these
 * two hooks add, and the README leads with it.
 *
 * The identity it is switching FROM is the audit login uid, which already chose
 * the policy — see struct cred_rule for why the momentary real uid is not a
 * usable source axis. As with the process controls, bpf_d_path is rejected here
 * so the image comes from pid_image.
 * ------------------------------------------------------------------------- */

/* The four id slots of a credential, in a fixed order shared by the new and old
 * sides so they can be compared positionally: real, effective, saved, fs. */
#define CRED_ID_SLOTS 4

/* Which slots this call actually moves, and what they move to. Positional —
 * changed[i] qualifies ids[i] — so no compaction and no variable-index write
 * into a stack array, which is the kind of thing the verifier makes expensive.
 * The same id landing in two slots is simply tested twice, which is harmless.
 *
 * SLOT-WISE, not "an id the task did not already hold anywhere". The difference
 * is the whole reason a rule against uid 0 works at all. su and sudo are
 * setuid-root binaries, so execve already put 0 in euid, suid and fsuid before
 * either of them runs a line of code; their later setuid(0) therefore acquires
 * nothing the task did not hold, and a rule matching only unheld ids would sit
 * there looking enforced while root was reached anyway (measured: `su root`
 * succeeded under a toUserID:0 deny, with no event). Comparing each slot to its
 * own previous value catches the real-uid move 1000 -> 0 that su performs.
 *
 * Nothing is lost by the change: an id absent from every old slot is by
 * definition absent from its own, so the old matches are a subset of these. The
 * no-op calls stay filtered, which is what keeps sudo's permission state
 * machine from flooding the ring buffer. */
struct cred_id_delta {
    __u32 ids[CRED_ID_SLOTS];   /* what each slot becomes */
    __u32 was[CRED_ID_SLOTS];   /* what it held before */
    __u8 changed[CRED_ID_SLOTS];
    __u8 any;
};

static __always_inline void cred_id_delta_of(struct cred_id_delta *out,
                                             const __u32 *new_ids,
                                             const __u32 *old_ids)
{
    out->any = 0;
#pragma unroll
    for (int i = 0; i < CRED_ID_SLOTS; i++) {
        __u8 changed = old_ids[i] != new_ids[i];

        out->ids[i] = new_ids[i];
        out->was[i] = old_ids[i];
        out->changed[i] = changed;
        if (changed) out->any = 1;
    }
}

/* Decide whether this call moves a slot the rule cares about, and describe that
 * one slot. When the rule names a destination it must be a slot that moved TO
 * it; when it names none, the first slot that moved at all — real, effective,
 * saved, fs, in that order.
 *
 * from and to come from the SAME slot on purpose. Reporting the old real uid
 * next to whichever id matched would render an effective-uid change of 1 -> 0
 * as "from_uid=0 to_uid=0", which reads as no change at all. */
static __always_inline __u8 delta_pick(const struct cred_id_delta *d,
                                       __u8 constrained, __u32 want,
                                       __u32 *from, __u32 *to)
{
    __u8 found = 0;

#pragma unroll
    for (int i = 0; i < CRED_ID_SLOTS; i++) {
        if (found || !d->changed[i]) continue;
        if (constrained && d->ids[i] != want) continue;
        found = 1;
        *from = d->was[i];
        *to = d->ids[i];
    }
    return found;
}

struct cred_check_ctx {
    void *inner;
    const char *policy_id;
    const char *exec_path;      /* the switching process's image, or NULL */
    const struct cred_id_delta *delta;
    __u32 exec_path_len;
    __u32 uid;                  /* login uid; the policy key and the event's */
    __u32 employee_id;
    __u32 count;
    __u8 op;                    /* OP_SETUID or OP_SETGID */
    __u8 op_bit;                /* the same, as the CRED_OP_*_BIT a rule matches */
    __u8 setid_flags;           /* LSM_SETID_*, for the event only */
    __u8 matched;
    int result;
};

static long check_cred_rule_cb(__u32 i, void *data)
{
    struct cred_check_ctx *ctx = data;
    __u32 zero = 0, index, to_id;
    struct cred_policy_slot *slot;
    struct cred_rule *r;
    struct runtime_config *cfg;
    struct cred_event_ids ids;
    __u32 from_id = 0, want;
    __u8 denied, status, constrained;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;

    /* One array holds the rules for both operations, so skip the ones that do
     * not cover this one — the same gate proc rules open with, and what keeps
     * first-match-wins meaningful for each operation independently. */
    if (!(r->op_mask & ctx->op_bit)) return 0;

    /* Cheapest first: the destination id is four scalar compares, the employee
     * one more, and only then the single pattern scan. */
    constrained = ctx->op == OP_SETUID ? r->has_to_uid : r->has_to_gid;
    want = ctx->op == OP_SETUID ? r->to_uid : r->to_gid;
    if (!delta_pick(ctx->delta, constrained, want, &from_id, &to_id)) return 0;
    if (r->employee_id != EMPLOYEE_ID_ANY && r->employee_id != ctx->employee_id)
        return 0;

    if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
        if (!ctx->exec_path) return 0;
        if (!match_path_pattern(r->exec_path, r->exec_wild, r->exec_suffix_len,
                                ctx->exec_path, ctx->exec_path_len))
            return 0;
    }

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    if (!r->no_event) {
        ids.from_id = from_id;
        ids.to_id = to_id;
        ids.flags = ctx->setid_flags;
        /* No path: nothing is being acted on but the task's own identity. The
         * image that is doing it goes in executable_path, as everywhere else. */
        emit_event(ctx->uid, ctx->op, status, "", ctx->exec_path,
                   ctx->policy_id, 1, 0, &ids);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;   /* FIRST MATCH WINS */
}

static __always_inline int check_cred_policy(const struct cred *new_cred,
                                             const struct cred *old_cred,
                                             __u8 op, __u8 op_bit, int flags)
{
    __u32 uid, zero = 0, count;
    __u32 new_ids[CRED_ID_SLOTS], old_ids[CRED_ID_SLOTS];
    struct cred_id_delta delta;
    struct task_struct *task;
    struct cred_policy_slot *meta;
    struct cred_check_ctx ctx;
    struct pid_image *self_img;
    void *inner;

    if (task_is_exempt()) return 0;

    /* op is a constant at each call site, so only one of these survives. */
    if (op == OP_SETUID) {
        new_ids[0] = BPF_CORE_READ(new_cred, uid.val);
        new_ids[1] = BPF_CORE_READ(new_cred, euid.val);
        new_ids[2] = BPF_CORE_READ(new_cred, suid.val);
        new_ids[3] = BPF_CORE_READ(new_cred, fsuid.val);
        old_ids[0] = BPF_CORE_READ(old_cred, uid.val);
        old_ids[1] = BPF_CORE_READ(old_cred, euid.val);
        old_ids[2] = BPF_CORE_READ(old_cred, suid.val);
        old_ids[3] = BPF_CORE_READ(old_cred, fsuid.val);
    } else {
        new_ids[0] = BPF_CORE_READ(new_cred, gid.val);
        new_ids[1] = BPF_CORE_READ(new_cred, egid.val);
        new_ids[2] = BPF_CORE_READ(new_cred, sgid.val);
        new_ids[3] = BPF_CORE_READ(new_cred, fsgid.val);
        old_ids[0] = BPF_CORE_READ(old_cred, gid.val);
        old_ids[1] = BPF_CORE_READ(old_cred, egid.val);
        old_ids[2] = BPF_CORE_READ(old_cred, sgid.val);
        old_ids[3] = BPF_CORE_READ(old_cred, fsgid.val);
    }
    cred_id_delta_of(&delta, new_ids, old_ids);
    /* Before the map lookup on purpose. The kernel calls these hooks on every
     * setuid-family syscall including the ones that change nothing, and sudo
     * alone makes a dozen of those per run; a call that moves no slot cannot be
     * what any rule here is about. */
    if (!delta.any) return 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&active_cred_policy_by_uid, &uid);
    if (!inner) return 0;
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) return 0;
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) return 0;

    self_img = task_image(task);
    ctx = (struct cred_check_ctx){
        .inner = inner,
        .policy_id = meta->meta.id,
        .exec_path = self_img ? self_img->exe_path : 0,
        .delta = &delta,
        .exec_path_len = self_img ? self_img->path_len : 0,
        .uid = uid,
        .employee_id = current_employee_id(task, uid),
        .count = count,
        .op = op,
        .op_bit = op_bit,
        .setid_flags = (__u8)flags,
    };
    bpf_loop(MAX_RULES, check_cred_rule_cb, &ctx, 0);
    return ctx.result;
}

/*
 * setuid(2) and its relatives — setreuid, setresuid, setfsuid. This is the hook
 * su and sudo trip when they switch user, and denying it makes them fail with
 * "cannot set user id" rather than silently proceed.
 *
 * Called before the new credentials are committed, so bpf_get_current_uid_gid()
 * inside emit_event still reports the old real uid.
 *
 * One caveat worth knowing: __sys_setfsuid discards the LSM error and returns
 * the old fsuid with no errno at all. A deny on an LSM_SETID_FS change is
 * therefore audited but not felt by the caller.
 */
SEC("lsm/task_fix_setuid")
long BPF_PROG(check_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{
    return lsm_ret(check_cred_policy(new, old, OP_SETUID, CRED_OP_SETUID_BIT, flags));
}

/*
 * setgid(2) and its relatives. Its own hook and its own selector because a
 * kernel that predates 5.13 has no task_fix_setgid to attach to.
 *
 * This covers the PRIMARY group only. security_task_fix_setgroups, which would
 * cover the supplementary list that initgroups() sets, does not exist on the
 * RHEL 9 kernels this runs on, so joining a privileged group that way is not
 * visible here. The README says so plainly.
 */
SEC("lsm/task_fix_setgid")
long BPF_PROG(check_task_fix_setgid, struct cred *new, const struct cred *old, int flags)
{
    return lsm_ret(check_cred_policy(new, old, OP_SETGID, CRED_OP_SETGID_BIT, flags));
}

/* Resolve the image about to be executed and stage it for pid_image.
 *
 * Called for EVERY exec, before task_is_exempt() has a say. That is deliberate
 * and is the whole point: tasks with no audit session are the systemd-started
 * daemons — sshd, wdog, the database — and they are exactly what a kill rule
 * is written to protect. Recording only the tasks the file policy judges would
 * leave the protected set empty. */
static __always_inline void stage_exec_image(struct file *file)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32), zero = 0;
    struct file_path_scratch *ps;
    struct pid_image *img;
    long len;

    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!ps) return;
    ps->path[0] = '\0';
    /* A second bpf_d_path on the exec path, since check() below resolves its
     * own and returns early for exempt tasks before it gets there. exec is
     * rare enough next to open() that unifying the two is not worth the
     * contortion it would take. */
    len = bpf_d_path(&file->f_path, ps->path, PATH_LEN);
    if (len <= 0) return;
    img = bpf_map_lookup_elem(&pending_image_scratch, &zero);
    if (!img) return;
    img->start_clock = 0;   /* filled at the tracepoint, once the exec is real */
    img->path_len = (__u32)len - 1;
    img->_pad = 0;
    bpf_probe_read_kernel_str(img->exe_path, sizeof(img->exe_path), ps->path);
    bpf_map_update_elem(&pending_image, &pid, img, BPF_ANY);
}

SEC("lsm/bprm_check_security")
long BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    if (ret) return lsm_ret(ret);
    if (!bprm->file) return 0;
    stage_exec_image(bprm->file);
    return lsm_ret(check(bprm->file, OP_EXEC));
}

SEC("lsm/file_open")
long BPF_PROG(check_file_open, struct file *file, int ret)
{
    __u32 mode;

    if (ret) return lsm_ret(ret);
    mode = BPF_CORE_READ(file, f_mode);
    if (mode & FMODE_WRITE) {
        ret = check(file, OP_WRITE);
        if (ret) return lsm_ret(ret);
    }
    if (mode & FMODE_READ) return lsm_ret(check(file, OP_READ));
    return 0;
}

SEC("lsm/path_unlink")
long BPF_PROG(check_path_unlink, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_rmdir")
long BPF_PROG(check_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_mkdir")
long BPF_PROG(check_path_mkdir, const struct path *dir, struct dentry *dentry,
             umode_t mode)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_MKDIR));
}

SEC("lsm/path_symlink")
long BPF_PROG(check_path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_SYMLINK));
}

SEC("lsm/path_link")
long BPF_PROG(check_path_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    /* Like rename, both sides are checked: hard-linking a protected file to a
     * new name must not become a way around rules on the original path. The
     * old side only provides a dentry, so it is resolved by the dentry walk. */
    int ret = check_dentry_op(old_dentry, OP_LINK);

    if (ret) return lsm_ret(ret);
    return lsm_ret(check_dir_dentry(new_dir, new_dentry, OP_LINK));
}

SEC("lsm/inode_mknod")
long BPF_PROG(check_inode_mknod, struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev)
{
    /* security_path_mknod is not in this kernel's bpf_d_path allowlist, so the
     * program attaches to inode_mknod instead and rebuilds the path from the
     * new dentry's parent chain, sharing inode_setattr's mount-prefix caveat.
     * mknod(S_IFREG) is not seen here, but regular-file creation is already
     * governed by file_open(O_CREAT). */
    return lsm_ret(check_dentry_op(dentry, OP_MKNOD));
}

SEC("lsm/path_rename")
long BPF_PROG(check_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    /* Both sides are writes: moving a file out of a protected directory and
     * moving one in are each subject to the write rules. */
    int ret = check_dir_dentry(old_dir, old_dentry, OP_RENAME);

    if (ret) return lsm_ret(ret);
    return lsm_ret(check_dir_dentry(new_dir, new_dentry, OP_RENAME));
}

SEC("lsm/path_chmod")
long BPF_PROG(check_path_chmod, const struct path *path, umode_t mode)
{
    return lsm_ret(check_path_op(path, OP_CHMOD));
}

SEC("lsm/path_chown")
long BPF_PROG(check_path_chown, const struct path *path)
{
    return lsm_ret(check_path_op(path, OP_CHOWN));
}

SEC("lsm/path_truncate")
long BPF_PROG(check_path_truncate, const struct path *path)
{
    /* Path-based truncate()/truncate64() never opens the file, so
     * file_open(FMODE_WRITE) does not see it. Governing it here closes a
     * write-class bypass that would otherwise let a protected file be zeroed
     * without matching any rule. (ftruncate(fd) is already covered by
     * file_open, and O_TRUNC opens carry FMODE_WRITE there too.) */
    return lsm_ret(check_path_op(path, OP_TRUNCATE));
}

SEC("lsm/inode_setattr")
long BPF_PROG(check_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
    __u32 ia_valid = BPF_CORE_READ(attr, ia_valid);

    /* Only explicit mtime changes (utimes/utimensat). chmod/chown pass through
     * here too but carry no MTIME bit, and size changes (ATTR_SIZE) are
     * governed by path_truncate / file_open, so they are ignored here to avoid
     * double-accounting the same write. */
    if (!(ia_valid & (ATTR_MTIME | ATTR_MTIME_SET)) || (ia_valid & ATTR_SIZE))
        return 0;
    return lsm_ret(check_dentry_op(dentry, OP_SETTIME));
}

SEC("tracepoint/sched/sched_process_exec")
int emit_committed_exec(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct pending_exec_event *pending;
    struct pid_image *staged;

    /* The exec is now real, so the image staged in bprm_check becomes this
     * process's current one. Done before the event below because it must
     * happen for every exec, and the event only fires for some. */
    staged = bpf_map_lookup_elem(&pending_image, &pid);
    if (staged) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

        staged->start_clock = BPF_CORE_READ(task, start_boottime) / NSEC_PER_CLOCK;
        bpf_map_update_elem(&pid_image, &pid, staged, BPF_ANY);
        bpf_map_delete_elem(&pending_image, &pid);
    }

    pending = bpf_map_lookup_elem(&pending_execs, &pid);
    if (!pending) return 0;
    emit_event(pending->uid, OP_EXEC, pending->status, pending->file,
               pending->executable_path, pending->policy_id, 1, 0, 0);
    bpf_map_delete_elem(&pending_execs, &pid);
    return 0;
}

/* A process that forks without ever calling exec keeps running its parent's
 * image — a subshell of /bin/bash is still /bin/bash. Without this the child
 * would have no entry at all and would match no target_path rule, which for a
 * deny rule means the protection silently does not apply to it. */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(track_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 ppid = BPF_CORE_READ(parent, tgid), cpid = BPF_CORE_READ(child, tgid);
    __u32 zero = 0;
    struct pid_image *pimg, *copy;

    if (ppid == cpid) return 0;         /* a new thread, not a new process */
    pimg = bpf_map_lookup_elem(&pid_image, &ppid);
    if (!pimg) return 0;
    /* Copied through scratch rather than edited in place: pimg points into the
     * parent's map value, and stamping the child's start time onto it would
     * corrupt the parent's entry and make it fail its own staleness check. */
    copy = bpf_map_lookup_elem(&pending_image_scratch, &zero);
    if (!copy) return 0;
    __builtin_memcpy(copy, pimg, sizeof(*copy));
    /* The child gets its own start time: the entry must stay verifiable
     * against the task it now describes, not the one it was copied from. */
    copy->start_clock = BPF_CORE_READ(child, start_boottime) / NSEC_PER_CLOCK;
    bpf_map_update_elem(&pid_image, &cpid, copy, BPF_ANY);
    return 0;
}

/* Drop the entry when the process is gone. The LRU would eventually reclaim it
 * and start_clock would catch a reused pid regardless, but neither is a reason
 * to leave the table full of the dead. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(track_exit, struct task_struct *task)
{
    __u32 pid = BPF_CORE_READ(task, pid), tgid = BPF_CORE_READ(task, tgid);

    if (pid != tgid) return 0;          /* a thread exiting, not the process */
    bpf_map_delete_elem(&pid_image, &tgid);
    bpf_map_delete_elem(&pending_image, &tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
