/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:9-155, before the split. */
#ifndef DOOR_FILE_CONST_H
#define DOOR_FILE_CONST_H

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
/* Employee names are short human identifiers, not paths; 64 bytes leaves room
 * for a 63-character name plus its NUL. Rules do not store the name — see
 * struct rule::employee_id — but the session record and the intern table do. */
#define EMPLOYEE_NAME_LEN 64
/* The two reporting-only strings on the session record. Neither is ever matched
 * against, in the kernel or out of it — they exist to be printed.
 *
 * 32 covers every PAM service name a distro ships with room to spare
 * ("gdm-autologin" is the longest that comes to mind at 13), and a longer one is
 * truncated rather than rejected: the classification has already happened by
 * then and does not depend on this string.
 *
 * 64 for rhost holds any IPv6 literal (INET6_ADDRSTRLEN is 46) and the great
 * majority of hostnames. A hostname longer than 63 characters is truncated, and
 * it is worth being clear that this is acceptable ONLY because nothing decides
 * anything from this field — a truncated address that were matched against
 * would be a security bug, and this one is a log line. */
#define SESSION_SERVICE_LEN 32
#define SESSION_RHOST_LEN   64
/* A rule that constrains no employee, and the id of a session whose employee
 * is unknown. The two meeting is what makes an unidentified session match only
 * the rules that name nobody. */
#define EMPLOYEE_ID_ANY 0

/* Where a login session came from — the third user axis, after the login uid
 * that selects the policy and the employee that selects which of its rules
 * apply. It answers the one question the first two cannot: a child of sshd and
 * a child of crond carry the SAME login uid and the SAME audit session id, and
 * under the axes above they are the same thing. They are not.
 *
 * This is a property of the login session, not of the process. pam_wood.so
 * classifies it once at open_session — it runs inside sshd's or crond's address
 * space, so PAM_SERVICE and PAM_RHOST are right there — and writes it into
 * session_identity. Every descendant inherits it for free through
 * task->sessionid, which is why nothing here walks a process tree: ancestry
 * decays (setsid, nohup past logout, a shell under tmux), and an audit session
 * id does not. It survives su and sudo for the same reason the login uid does —
 * neither runs pam_loginuid, so neither opens a new session.
 *
 * Tasks with NO PAM session (sessionid == -1: systemd units started by pid 1,
 * kernel threads) never reach a rule loop at all — task_is_exempt() turns them
 * away first — so they have no value here. Everything below is a distinction
 * BETWEEN sessions that exist.
 *
 * ORIGIN_UNKNOWN is not a failure to be papered over. A stack that never got
 * the module, a record lost to a reap, a session opened before wdog started —
 * all land here, and a rule constraining origin does not match them. That is
 * the same fail-to-not-match direction current_session_axes() takes for the
 * employee: "deny what cannot be placed" is written as a rule naming
 * ORIGIN_UNKNOWN, out loud, rather than happening by omission. */
#define ORIGIN_UNKNOWN   0u  /* not classified; see above — never silently denied */
#define ORIGIN_REMOTE    1u  /* a person, over the network. sshd */
#define ORIGIN_CONSOLE   2u  /* a person, at the machine. login, gdm */
#define ORIGIN_SCHEDULED 3u  /* no person; a timetable started it. crond, atd */
#define ORIGIN_SERVICE   4u  /* a session manager. systemd-user */
#define ORIGIN_MAX       ORIGIN_SERVICE

/* session_identity.origin carries the origin in its low byte and flags in its
 * high bits. The field is a __u32 holding values 0..ORIGIN_MAX, so the room was
 * already there — which is the whole reason the flag lives here rather than in a
 * field of its own. Growing the struct is a deployment hazard (see
 * door/file_types.h): it invalidates the pin, and a pam_wood.so built against
 * the old layout hands the kernel the difference in bytes of its own stack.
 * Riding in spare bits costs none of that.
 *
 * SESSION_CLOSED means pam_wood.so has run close_session for this session — the
 * login is over — while at least one process still carries its audit session id.
 * That state is ordinary rather than exceptional: a VS Code or JetBrains remote
 * server whose bootstrap ssh exits immediately, anything under nohup, setsid,
 * tmux or screen past logout. Those processes keep task->sessionid forever, and
 * before this flag existed the record was DELETED at close_session, so they lost
 * both user axes — employee and origin — for the rest of their lives. The most
 * long-lived processes on a host were the ones policy could not place.
 *
 * NOTHING IN THE KERNEL BRANCHES ON IT. The origin keeps matching exactly as it
 * did while the session was open, which is the point: origin is a property of
 * the session, and the session's processes are still here. The flag exists so an
 * audit line can say the login behind them has ended, and so wdog's reaper can
 * tell an ordinary cleanup from a session that never reached close_session at
 * all (cmd/wdog/session.go, sweep). */
#define SESSION_CLOSED   (1u << 31)
/* Extracts the origin from that field. Every reader must go through this: a
 * record written by a newer pam_wood.so has the flag set, and comparing the raw
 * field against ORIGIN_MAX would place such a session on the unknown bit. That
 * is also precisely what an OLDER build does with a newer module's record, and
 * it is the safe direction — fail to not-match, as everywhere else on this axis
 * — but it is degraded behaviour, not the intent. Hence the rule that the module
 * and the daemons ship together; see pam/pam.c. */
#define ORIGIN_VALUE(x)  ((x) & 0xffu)

/* The session record stores one value; a rule stores a MASK of them, so a
 * single rule can say "remote or console" without being written twice. Zero is
 * "this rule constrains no origin", which is what every rule predating the axis
 * carries — that is what keeps an installed policy's meaning bit for bit
 * unchanged. See struct rule::origin_mask. */
#define ORIGIN_BIT(x) ((__u8)(1u << (x)))
/* Converts start_boottime to the units /proc/<pid>/stat reports. USER_HZ is 100
 * in the kernel's /proc ABI regardless of CONFIG_HZ, and fs/proc/array.c derives
 * starttime from the same start_boottime, so dividing here reproduces that field
 * exactly rather than approximately — which is what lets wdog prime wax_pid_image
 * from /proc and have the entries pass their own staleness check. */
#define NSEC_PER_CLOCK 10000000ULL
/* Policy IDs are typically 32-character strings; 39 bytes + NUL also covers
 * dashed UUIDs, and 40 keeps the fields after it naturally aligned. */
#define POLICY_ID_LEN 40
#define MAX_RULES 512
/* Slot 0 of an inner policy map holds the metadata, so a rule always sits at
 * 1 + its position in the config array and slot 0 can never name one. That is
 * what makes it usable as the event's "no rule matched" value — and it is also
 * what a record produced by an older object, whose bytes there are zero, reports.
 * The alternative, an all-ones sentinel, would make such a record claim rule 0. */
#define RULE_SLOT_NONE 0u
#define OP_EXEC    1
#define OP_READ    2
#define OP_WRITE   3
/* Operations below change the filesystem. Most are governed by PERM_WRITE, but
 * the two that make a name disappear — OP_UNLINK (unlink and rmdir) and
 * OP_RENAME — are governed by PERM_DELETE instead. See op_perm_mask(). */
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
/* Internal only, and never reported: the destination side of a rename. It
 * exists solely to give that side a different permission mask from the source
 * (see op_perm_mask), and check_policy normalizes it back to OP_RENAME before
 * anything can observe it, so events carry 5 for both sides. 18-19 are the
 * remainder of the gap before the network codes in net.c. */
#define OP_RENAME_TO 18

/* Reading the NAMES out of a directory: getdents(2)/getdents64(2), judged at the
 * security_file_permission() call that opens iterate_dir(). Distinct from
 * OP_READ, which is still what file_open reports for opendir() — holding a
 * directory handle and enumerating what is inside it are different acts, and
 * PERM_LIST below is what tells them apart. 19 is the last of the gap before the
 * network codes in net.c. */
#define OP_READDIR 19

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
/* include/linux/fs.h. The mask argument of security_file_permission():
 * iterate_dir() passes MAY_READ, rw_verify_area() passes MAY_READ or MAY_WRITE. */
#define MAY_READ  0x00000004
/* include/linux/stat.h file-type bits. BTF carries types, not macros, which is
 * why FMODE_READ above is spelled out too. Kept identical to the copy in
 * door/self_const.h — that object needs S_IFCHR/S_IFBLK as well, this one only
 * needs to ask "is this a directory". */
#define S_IFMT  0170000
#define S_IFDIR 0040000
/* include/linux/fs.h iattr ia_valid flags */
#define ATTR_SIZE      (1 << 3)
#define ATTR_MTIME     (1 << 5)
#define ATTR_MTIME_SET (1 << 8)
#define MAX_DENTRY_DEPTH 48
#define MAX_CGROUP_DEPTH 32
#define MODE_ENFORCE 0
#define MODE_WARN    1
/* Permission bits selecting which operations a rule governs.
 *
 * PERM_DELETE does not overlap PERM_WRITE: it was carved out of it. Making a
 * name disappear — unlink, rmdir, and the source side of a rename — is judged
 * by PERM_DELETE alone, so a rule carrying only PERM_WRITE no longer stops rm
 * or mv. That is a deliberate break with the earlier behaviour, and the
 * userspace loader warns about deny rules that look like they predate it; the
 * old meaning is written as PERM_WRITE|PERM_DELETE (12).
 *
 * What PERM_DELETE is NOT is content destruction. truncate(), O_TRUNC and a
 * plain overwrite leave the name in place and stay under PERM_WRITE. A rule
 * that means to keep a file's contents intact needs the write bit.
 *
 * PERM_LIST, unlike PERM_DELETE, was NOT carved out of anything. read(2) governs
 * opening a directory and always did; list(16) governs only what happens on the
 * fd afterwards, which nothing governed before it existed. No installed rule
 * changes meaning when a daemon carrying this bit takes over — a read-deny that
 * stopped opendir() yesterday stops it today. What it does not do, and never
 * did, is stop a directory fd that was opened before the rule was written, or
 * one inherited across exec, or one passed over SCM_RIGHTS. That is the gap
 * list(16) closes, and it is why the loader warns about read-denies that do not
 * carry it.
 *
 * Note that "all bits" is now 31, not 15. */
#define PERM_EXEC   1
#define PERM_READ   2
#define PERM_WRITE  4
#define PERM_DELETE 8
#define PERM_LIST   16

/* The one place an operation is mapped to the permission bits that govern it.
 * The result is a mask, not a single bit: a rule matches when it carries any of
 * them, so the rename destination below is reachable from either axis.
 *
 * Called once per check from check_policy, outside bpf_loop, so the switch
 * costs nothing the verifier cares about. */
static __always_inline __u8 op_perm_mask(__u8 op)
{
    switch (op) {
    case OP_EXEC:      return PERM_EXEC;
    case OP_READ:      return PERM_READ;
    /* Enumeration only. The open that produced the fd was judged as OP_READ
     * against PERM_READ, and still is; this bit says nothing about it. */
    case OP_READDIR:   return PERM_LIST;
    /* OP_UNLINK is both unlink(2) and rmdir(2) — they share the op code, so
     * there is no way to write a rule covering one but not the other. */
    case OP_UNLINK:
    /* The source side of a rename: the name goes away, exactly as with unlink. */
    case OP_RENAME:    return PERM_DELETE;
    /* The destination side is both things at once, and needs both bits for the
     * same reason. Dropping PERM_WRITE would let `mv evil /etc/passwd` past a
     * write-deny that stops it today, which is a retreat in write protection
     * that has nothing to do with splitting delete out. Dropping PERM_DELETE
     * would let a rename destroy the very file a delete-deny names, since
     * renaming onto an existing name unlinks it. Fail closed on both.
     *
     * The cost is one false positive: a delete-deny also refuses a rename into
     * the protected path that overwrites nothing. */
    case OP_RENAME_TO: return PERM_WRITE | PERM_DELETE;
    default:           return PERM_WRITE;
    }
}

/* A rule suppresses events per operation, not for the rule as a whole: a rule
 * carrying PERM_READ|PERM_WRITE can drop the read noise and keep the write
 * record. no_event_s and no_event_fw are therefore masks in the rule's OWN
 * operation namespace — permission bits for struct rule and net_rule, op_mask
 * bits for proc_rule and cred_rule — naming the operations whose 'S', and whose
 * 'F' and 'W', are not reported.
 *
 * The status bits below are the userspace spelling of the same thing, and are
 * still what ingress_rule::no_event carries: an ingress rule judges one
 * operation class, so it has no axis to key on. See net_ingress.h, which is the
 * one caller that expands them.
 *
 * The loader writes both masks from model.NoEvent, which accepts either the old
 * number — one status mask over every operation the rule covers — or an object
 * naming operations one at a time. The number is not a legacy path: it expands
 * to exactly the mask the rule already carries, so the two spellings agree bit
 * for bit where they overlap.
 *
 * Duplicated in door/net_const.h; the two objects share no header. */
#define NO_EVENT_SUCCESS 1  /* suppress 'S' */
#define NO_EVENT_DENY    2  /* suppress 'F' and 'W' */

/* The one place the two masks are applied, at all five decision sites.
 *
 * eff is the operations THIS check demanded that the rule also carries — the
 * same intersection that let the rule match, so it is never zero here. Emit
 * unless every one of those operations is suppressed: silence takes naming all
 * of them, and a rule that half-suppresses still speaks. That matters for the
 * destination side of a rename, which demands PERM_WRITE|PERM_DELETE at once
 * (see op_perm_mask) — suppressing only write leaves the delete side reporting,
 * which is the same fail-loud direction op_perm_mask itself chose.
 *
 * Cost over the flag it replaces: one more byte loaded and one AND-NOT. Both
 * arms of the select are still compile-time-constant field offsets on a struct
 * already in registers, and status was computed two lines earlier from the same
 * r->deny. It sits at the tail of a bpf_loop callback whose every path then
 * falls into one `return 1`, so the verifier explores nothing twice: unlike the
 * pointer branch struct rule::employee_id describes, this one is BEHIND both
 * glob matchers rather than ahead of them. */
static __always_inline int rule_emits(__u8 eff, __u8 no_event_s,
                                      __u8 no_event_fw, __u8 status)
{
    __u8 suppressed = (status == 'S') ? no_event_s : no_event_fw;

    return (eff & ~suppressed) != 0;
}

#endif /* DOOR_FILE_CONST_H */
