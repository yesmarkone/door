/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_MAPS_H
#define DOOR_SELF_MAPS_H

/* NONE of these maps is pinned, and that is the opposite of the choice
 * door/file_maps.h:103-139 makes for wax_session_identity.
 *
 * That map is pinned so state survives a wdog restart — a session that logged
 * in keeps its identity, and PAM can record a login while wdog is down. The
 * trust set below must have the exact opposite property. A restarted wdog that
 * inherited the previous run's wax_self_tasks would be trusting pids that no
 * longer exist, and on a busy host those numbers get reused. Everything here is
 * rebuilt from scratch on every start, which is also what makes a binary
 * upgrade safe: the replacement is protected by its own inode the moment the
 * new wdog comes up, with nothing stale to migrate. */

/* tgid -> the role we trust it in. Tiny on purpose: this holds wdog, Agent and
 * optionally PID 1, and nothing else ever belongs in it. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32); /* tgid */
    __type(value, struct self_task_val);
} wax_self_tasks SEC(".maps");

/* {dev,ino} -> what may not be done to it. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct self_ino_key);
    __type(value, struct self_ino_val);
} wax_self_inodes SEC(".maps");

/* i_rdev -> flags, for device nodes only.
 *
 * A device node cannot be protected by {dev,ino}: an attacker who cannot touch
 * /dev/mem can `mknod /tmp/m c 1 1` and reach the same driver through a
 * different inode on a different filesystem. i_rdev is the part that does not
 * change. Looked up only behind an S_ISCHR/S_ISBLK test, so an ordinary open
 * never pays for it. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32); /* inode->i_rdev */
    __type(value, __u32); /* SELF_* */
} wax_self_rdevs SEC(".maps");

/* s_dev -> flags, consulted at sb_umount. Unmounting bpffs takes the pins with
 * it, which stops pam_wood.so finding wax_session_identity and silently ends
 * the employee axis for every login after it. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32); /* super_block->s_dev */
    __type(value, __u32); /* SELF_* */
} wax_self_devs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct self_config);
} wax_self_config SEC(".maps");

/* thread -> the session-map fd it was just handed. Set by wax_self_bpf_map,
 * consumed by wax_self_bpf on the next map command, which is what turns "someone
 * opened the identity map" into "session 42 logged in".
 *
 * THIS IS THE FIRST MAP HERE WHOSE ENTRIES AN UNTRUSTED CALLER CAN CAUSE TO
 * EXIST, so the header comment above no longer holds for all of them, and the
 * type is LRU for exactly that reason. A HASH returns -E2BIG once full, so
 * anyone able to open the pin 1024 times without issuing a command would blind
 * login detection for the whole host. LRU evicts the oldest instead: the worst
 * an attacker achieves is losing their own detection. Entries are also deleted
 * on consumption, so in normal operation the live set is around zero and an
 * eviction is itself abnormal.
 *
 * Keyed on bpf_get_current_pid_tgid() — the THREAD, not the tgid. "The syscall I
 * am about to make" is a per-thread fact, and a tgid key would let two threads
 * of a multi-threaded opener pair each other's opens with each other's commands. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); /* bpf_get_current_pid_tgid() */
    __type(value, struct self_pin_open);
} wax_self_pin_opens SEC(".maps");

/* Smaller than wax_events (1<<24) because these records are 64 bytes rather
 * than 1440, and because a host producing enough of them to fill 1MB is a host
 * where the first hundred already said everything. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} wax_self_events SEC(".maps");

/* Written by the loader with CollectionSpec.RewriteConstants BEFORE the
 * collection is built, so the verifier folds them into immediates and dead-code
 * eliminates the branches they guard. That is what keeps the loginuid test in
 * wax_self_open down to a compare against a constant on a hook that fires for
 * every open on the system. */

/* procfs's s_dev. Never changes for the life of a boot. 0 disables the
 * loginuid test entirely, which is what --self-loginuid=off does. */
volatile const __u32 self_proc_dev = 0;
/* "wax_" as a little-endian u32, compared against the first four bytes of a
 * map or program name. 0 disables the BPF-object guard. */
volatile const __u32 self_map_prefix = 0;
/* The first 8 bytes of "wax_sess", the prefix that identifies
 * wax_session_identity — the one map pam_wood.so must keep being able to open.
 * A u64 compare rather than a strncmp the verifier would have to unroll. */
volatile const __u64 self_session_map_prefix = 0;

#endif /* DOOR_SELF_MAPS_H */
