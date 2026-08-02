/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_TYPES_H
#define DOOR_SELF_TYPES_H

/* A filesystem object named by IDENTITY, not by path.
 *
 * dev is the superblock's s_dev — which filesystem — and ino its i_ino. What
 * makes this the right key, and a path string the wrong one, is the list of
 * things that change the path and leave this pair alone: a second hard link, a
 * bind mount, a rename, and a bpf_d_path that simply failed. That last one is
 * not hypothetical: door/file_path.h:25,50,67,86 all return "allow" when path
 * resolution fails, so every path-based protection inherits a fail-open the
 * moment the helper declines. This does not.
 *
 * _pad is load-bearing, exactly as struct employee_name_key's zero padding is
 * (door/file_types.h): a hash key is compared as a fixed block of bytes, so a
 * key assembled on the stack with junk in the hole looks up nothing at all. */
struct self_ino_key {
    __u64 ino; /*  0 — inode->i_ino */
    __u32 dev; /*  8 — inode->i_sb->s_dev, in the KERNEL's dev_t encoding.
                *      NOT what stat(2) reports; see kdev() in cmd/wdog/self.go */
    __u32 _pad; /* 12 */
};
_Static_assert(sizeof(struct self_ino_key) == 16,
               "self_ino_key must stay 16 bytes");
_Static_assert(__builtin_offsetof(struct self_ino_key, dev) == 8,
               "self_ino_key.dev must stay at offset 8 (cmd/wdog/self.go)");

struct self_ino_val {
    __u32 flags;   /* 0 — SELF_* */
    __u8  kind;    /* 4 — SKIND_*, carried on the event only */
    __u8  _pad[3]; /* 5 */
};
_Static_assert(sizeof(struct self_ino_val) == 8,
               "self_ino_val must stay 8 bytes");
_Static_assert(__builtin_offsetof(struct self_ino_val, kind) == 4,
               "self_ino_val.kind must stay at offset 4 (cmd/wdog/self.go)");

/* A task this daemon trusts with its own internals: wdog, Agent, and — unless
 * --self-kill=strict — the init a `systemctl stop` speaks through.
 *
 * start_clock is the same staleness guard struct pid_image carries
 * (door/file_types.h): start_boottime in the 1/100s units /proc/<pid>/stat
 * reports. Strictly it is belt and braces — a pid cannot be reused while its
 * owner is alive, and if wdog dies every link here closes with it — but it is
 * one read and one compare, and it removes the question. 0 means "do not
 * check", which is what PID 1 gets, because wdog cannot know when init booted
 * relative to its own clock without reading /proc/1/stat for no benefit. */
struct self_task_val {
    __u64 start_clock; /* 0 */
    __u32 role;        /* 8 — SROLE_* */
    __u32 _pad;        /* 12 */
};
_Static_assert(sizeof(struct self_task_val) == 16,
               "self_task_val must stay 16 bytes");

/* This layer's own switch. Deliberately NOT wax_runtime_config_map.
 *
 * `tdog mode warn` is the operator's emergency release of the POLICY, and
 * docs/policy.md documents it as exactly that — the thing to reach for
 * mid-incident. It must therefore NOT also release the daemon's protection of
 * itself, or the one command an operator is told to trust in an emergency is
 * also the one command an attacker is told to run. Separate map, separate RPC,
 * separate authority. See docs/self-defense.md. */
struct self_config {
    __u64 lockdown_mask; /*  0 — 1ULL << enum lockdown_reason, refused */
    __u8  mode;          /*  8 — SMODE_* */
    __u8  sealed;        /*  9 — refuses the transition to WARN or DISARMED */
    __u16 flags;         /* 10 — SCFG_* */
    __u32 _pad;          /* 12 */
};
_Static_assert(sizeof(struct self_config) == 16,
               "self_config must stay 16 bytes");
_Static_assert(__builtin_offsetof(struct self_config, mode) == 8,
               "self_config.mode must stay at offset 8 (cmd/wdog/self.go)");
_Static_assert(__builtin_offsetof(struct self_config, sealed) == 9,
               "self_config.sealed must stay at offset 9 (cmd/wdog/self.go)");
_Static_assert(__builtin_offsetof(struct self_config, flags) == 10,
               "self_config.flags must stay at offset 10 (cmd/wdog/self.go)");

/* 64 bytes, and that number is the design.
 *
 * struct event is 1440 (door/file_types.h) because it carries three paths, a
 * cgroup and a cmdline. This carries none of them: a path here would mean
 * calling bpf_d_path on hooks that are already the hottest in the system, and
 * the {dev,ino} below is something userspace can resolve back to a name for
 * free — wdog is the process that registered it. comm is the one identity
 * cheap enough to take unconditionally. */
struct self_event {
    __u64 timestamp_ns; /*  0 */
    __u64 ino;          /*  8 — the object, when the check had one */
    __u32 dev;          /* 16 */
    __u32 uid;          /* 20 — audit login uid, as everywhere else */
    __u32 real_uid;     /* 24 */
    __u32 pid;          /* 28 */
    __u32 ppid;         /* 32 */
    __u32 session_id;   /* 36 */
    __u32 target;       /* 40 — kill/ptrace tgid, bpf cmd, or lockdown reason */
    __u8  op;           /* 44 — SOP_* */
    __u8  status;       /* 45 — 'F' denied, 'W' would have denied */
    __u8  kind;         /* 46 — SKIND_* */
    __u8  detail;       /* 47 — signal number, ptrace mode, or fmode */
    char  comm[16];     /* 48 */
};
_Static_assert(sizeof(struct self_event) == 64,
               "self_event must stay 64 bytes");
_Static_assert(__builtin_offsetof(struct self_event, op) == 44,
               "self_event.op must stay at offset 44 (cmd/wdog/self_test.go)");
_Static_assert(__builtin_offsetof(struct self_event, comm) == 48,
               "self_event.comm must stay at offset 48 (cmd/wdog/self_test.go)");

#endif /* DOOR_SELF_TYPES_H */
