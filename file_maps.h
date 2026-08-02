/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:496-672. */
#ifndef DOOR_FILE_MAPS_H
#define DOOR_FILE_MAPS_H

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct policy_slot);
} wax_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(wax_policy_template));
} wax_active_policy_by_uid SEC(".maps");

/* Signal rules get their own array and their own map-in-map rather than
 * sharing the file rules': the slot layouts differ, and keeping the two apart
 * means neither loop walks past rules it can never match. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct proc_policy_slot);
} wax_proc_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(wax_proc_policy_template));
} wax_active_proc_policy_by_uid SEC(".maps");

/* Credential rules get a third array for the same reason the signal rules got a
 * second one: the slot is a different size, and a setuid check has no business
 * walking rules that can only ever match a signal. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct cred_policy_slot);
} wax_cred_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(wax_cred_policy_template));
} wax_active_cred_policy_by_uid SEC(".maps");

/* tgid -> the image that process is running.
 *
 * Written on exec (where bpf_d_path works), inherited on fork (a process that
 * forks without exec keeps its parent's image), and dropped on exit. wdog
 * primes it from /proc at startup, which is what covers the daemons that were
 * already running — and those are precisely the processes a kill rule is
 * usually written to protect.
 *
 * LRU rather than a plain hash: unlike wax_session_identity there is no external
 * writer to report an overflow, and losing an entry degrades to "image
 * unknown" rather than to a wrong answer. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); /* tgid */
    __type(value, struct pid_image);
} wax_pid_image SEC(".maps");

/* Staging for wax_pid_image, exactly mirroring wax_pending_execs' reason for existing:
 * bprm_check_security runs BEFORE the exec is committed, and the exec can still
 * fail afterwards. Recording the image straight from there would let a process
 * claim an image it never actually ran. The sched_process_exec tracepoint
 * promotes the entry once the new image is live. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pid_image);
} wax_pending_image SEC(".maps");

/* struct pid_image is 272 bytes — more than half the verifier's 512-byte call
 * stack, and the exec hook that fills one also calls check(). Assembled here
 * instead, like every other oversized record in this file. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pid_image);
} wax_img_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_config);
} wax_runtime_config_map SEC(".maps");

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
 * sessions that are already gone.
 *
 * 65536 rather than the 4096 this held originally, and the number is a security
 * bound rather than a capacity estimate. Filling the table is REACHABLE: audit
 * session ids are handed out one per login, the reaper needs two sweeps sixty
 * seconds apart to collect a dead one, and pam_wood.c returns PAM_SUCCESS when
 * the update fails — so roughly four thousand logins used to leave every
 * subsequent session unidentified, with every employeeName-scoped rule quietly
 * ceasing to match and nothing in the log but a PAM warning. At 72 bytes an
 * entry this costs about 4.7MB and moves that threshold out of reach.
 *
 * Changing max_entries changes the pinned map's shape, so checkPin
 * (cmd/wdog/session.go) refuses to start against a pin left by an older build.
 * That refusal is correct and its message already carries the remedy; see the
 * upgrade note in docs/deploy.md. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); /* audit session id */
    __type(value, struct session_identity);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wax_session_identity SEC(".maps");

/* Employee name -> the id rules carry, interned by the loader. Written only by
 * wdog, and only while installing policies; read here once per check.
 *
 * Ids are assigned in order of first appearance and never reused for as long as
 * wdog runs, so a policy replacement cannot silently repoint an id that rules
 * from the previous generation still reference.
 *
 * Pinned and shared exactly like wax_session_identity, and for the same reason: the
 * file and network objects have to agree on the id space. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct employee_name_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wax_employee_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} wax_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} wax_pending_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} wax_exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct executable_path_scratch);
} wax_executable_path_scratch SEC(".maps");

/* bpf_d_path output is kept off the BPF call stack. check() invokes policy
 * callbacks and path matchers, so a 256-byte local buffer would exceed the
 * verifier's 512-byte combined call-stack limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_path_scratch);
} wax_file_path_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dentry_walk_scratch);
} wax_dentry_walk_scratch_map SEC(".maps");

#endif /* DOOR_FILE_MAPS_H */
