/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_CONST_H
#define DOOR_SELF_CONST_H

/* What may not be done to a protected object. A mask rather than a flag,
 * because one entry describes a binary that must not be written AND must not be
 * mounted over, and those two are decided at different hooks. */
#define SELF_NO_WRITE  0x01 /* file_open(W), truncate, chmod, chown, setattr   */
#define SELF_NO_UNLINK 0x02 /* unlink, rmdir, rename source, link source       */
#define SELF_NO_MOUNT  0x04 /* sb_mount / move_mount with this as mountpoint   */
#define SELF_NO_READ   0x08 /* file_open(R) — the /proc/kcore class only       */
#define SELF_IS_DIR    0x10 /* also judged as the PARENT of a create or unlink */
#define SELF_NO_UMOUNT 0x20 /* the filesystem rooted here may not be unmounted */

/* Strength, in three steps. ARMED is 0 so a zero-initialised ARRAY slot — what
 * the map holds between its creation and the loader's first write — enforces.
 * Every other ordering of these values would make the startup window fail open. */
#define SMODE_ARMED    0
#define SMODE_WARN     1 /* judge everything, deny nothing, report 'W'         */
#define SMODE_DISARMED 2 /* skip the checks outright                           */

/* SCFG_HAVE_READ_GUARD is set by the loader when at least one published entry
 * carries SELF_NO_READ. Without it a read open never touches the inode hash at
 * all, which is what keeps the hottest hook in the system cheap in the common
 * case — no read-guarded object at all. */
#define SCFG_HAVE_READ_GUARD 0x0001
/* systemctl stop has to keep working, so PID 1 is allowed to signal us unless
 * the operator asked for --self-kill=strict. See wax_self_kill. */
#define SCFG_KILL_ALLOW_PID1 0x0002
/* Refuse BPF_LINK_CREATE for LSM attach types from untrusted tasks. Guards the
 * trampoline slots the file and network objects attach into ~45s later, and
 * costs nothing else: on this host nobody but wdog attaches a BPF LSM program. */
#define SCFG_BPF_LINK_GUARD  0x0004
/* Also refuse BPF_LINK_DETACH and BPF_LINK_GET_FD_BY_ID. Off by default and it
 * should stay that way unless an operator asks: bpf_link_new_fd() has no LSM
 * hook of its own, so this can only be enforced at the cmd level, where it
 * cannot tell OUR links from anyone else's — `bpftool link show` stops working
 * for every BPF user on the host. The narrow case it guards (a future kernel
 * giving tracing links a .detach) is not worth that by default. */
#define SCFG_BPF_LINK_STRICT 0x0010
/* Set when at least one published entry carries SELF_IS_DIR. Without it the
 * ancestor walk is skipped outright, so an operator running --protect-paths=
 * (empty) pays nothing for a tree set that does not exist. */
#define SCFG_HAVE_TREE_GUARD 0x0008

#define SROLE_WDOG  1
#define SROLE_AGENT 2
#define SROLE_INIT  3

/* Carried on the event so a reader can tell which of the protected things was
 * reached without resolving {dev,ino} back to a path first. */
#define SKIND_ANY        0
#define SKIND_WDOG       1
#define SKIND_AGENT      2
#define SKIND_BPF_OBJECT 3
#define SKIND_PAM        4
#define SKIND_PIN_DIR    5
#define SKIND_PIN        6
#define SKIND_SOCKET_DIR 7
#define SKIND_STORE      8
#define SKIND_INTEGRITY  9
#define SKIND_DEVICE     10
#define SKIND_MAP        11
#define SKIND_PROG       12
#define SKIND_LINK       13
#define SKIND_LOGINUID   14
#define SKIND_LOCKDOWN   15
#define SKIND_ANCESTOR   16

/* Operation codes. door/file_const.h owns 1..18 and door/net_const.h owns
 * 20..26; starting at 40 leaves room for either to grow without colliding. */
#define SOP_KILL     40
#define SOP_PTRACE   41
#define SOP_BPF      42
#define SOP_BPF_MAP  43
#define SOP_BPF_PROG 44
#define SOP_WRITE    45
#define SOP_READ     46
#define SOP_UNLINK   47
#define SOP_CREATE   48
#define SOP_MOUNT    49
#define SOP_UMOUNT   50
#define SOP_LOGINUID 51
#define SOP_RDEV     52
#define SOP_LOCKDOWN 53

/* From the kernel UAPI, not from vmlinux.h — BTF carries types, not macros, so
 * these have to be spelled out here. Both are stable ABI. */
#define PROC_SUPER_MAGIC 0x9fa0
#define BPF_FS_MAGIC     0xcafe4a11

/* Same values door/file_const.h:97-98 spells out, and for the same reason. */
#define FMODE_READ  0x00000001
#define FMODE_WRITE 0x00000002

#define S_IFMT  0170000
#define S_IFCHR 0020000
#define S_IFBLK 0060000

/* How far up the parent chain a tree-protected ancestor is looked for. This is
 * a verifier ceiling, not a cost: bpf_loop charges per ACTUAL iteration and the
 * callback exits as soon as it matches or reaches the filesystem root, so a
 * typical path costs three to eight. The same number door/file_const.h:103 uses
 * for its own dentry walk, so the two agree on what "too deep" means. */
#define MAX_SELF_DEPTH 48

/* Converts start_boottime to the units /proc/<pid>/stat reports, so the
 * loader can prime start_clock from procStartClock() (cmd/wdog/image.go) and
 * have the two compare exactly rather than approximately.
 *
 * COPIED FROM door/file_const.h:23 — keep in sync. */
#define NSEC_PER_CLOCK 10000000ULL

#endif /* DOOR_SELF_CONST_H */
