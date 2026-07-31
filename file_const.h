/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:9-155. */
#ifndef DOOR_FILE_CONST_H
#define DOOR_FILE_CONST_H

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
 * that means to keep a file's contents intact needs the write bit. */
#define PERM_EXEC   1
#define PERM_READ   2
#define PERM_WRITE  4
#define PERM_DELETE 8

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

#endif /* DOOR_FILE_CONST_H */
