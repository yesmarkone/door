/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:364-463, before the split. */
#ifndef DOOR_NET_MAPS_H
#define DOOR_NET_MAPS_H

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_policy_slot);
} wax_net_policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(wax_net_policy_template));
} wax_active_net_policy_by_uid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_runtime_config);
} wax_net_runtime_config_map SEC(".maps");

/* The login uids that have a policy of their own — the set the host fallback
 * policy at FALLBACK_UID does not cover. NOT the map file.c declares, unlike
 * wax_session_identity below: this one is deliberately unpinned, so each object
 * gets its own copy and wdog writes both from one source. That is the same
 * split, and for the same reason, as wax_net_runtime_config_map above.
 *
 * Unpinned because the answer must not outlive wdog. A stale pin claiming a uid
 * is managed, read by a restarted wdog that has not yet replayed its policies,
 * would exempt that uid from the fallback during exactly the window the fallback
 * exists to cover. door/file_maps.h carries the rest of the reasoning, including
 * why the value is a presence flag and must never become a per-space bitmask. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);  /* KEEP IN SYNC with door/file_maps.h */
    __type(key, __u32);         /* login uid */
    __type(value, __u8);
} wax_net_managed_uids SEC(".maps");

/* The fallback policy's load-time gate for this object; see wax_fallback_on in
 * door/file_maps.h. Separate from the file object's so the two can be retreated
 * independently — wax_check_sendmsg is the program with the least verifier
 * budget left, and --fallback-policy=file exists to leave it out while the file,
 * process and credential controls keep theirs. */
volatile const __u8 wax_net_fallback_on = 0;

/* Audit session id -> the employee PAM logged in on it. THE SAME MAP file.c
 * declares, not a copy: LIBBPF_PIN_BY_NAME means whichever object loads second
 * attaches to the one the first created, which is the only way these two
 * objects can share state. Every attribute below must therefore stay identical
 * to file.c's declaration, or the second load fails on a layout mismatch. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); /* KEEP IN SYNC with door/file_maps.h */
    __type(key, __u32);         /* audit session id */
    __type(value, struct session_identity);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wax_session_identity SEC(".maps");

/* Employee name -> the id rules carry. THE SAME MAP file.c declares, shared
 * through its pin; both objects must resolve a name to the same id. Every
 * attribute must stay identical to file.c's declaration. */
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
} wax_net_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct net_cache_key);
    __type(value, struct net_cache_val);
} wax_net_verdict_cache SEC(".maps");

/* The ingress policy: one global array, not keyed by anything. Slot 0 is the
 * metadata, slots 1..rule_count the ordered rules — the same shape as an inner
 * policy map, minus the uid dimension it has no use for. Mode and generation
 * come from wax_net_runtime_config_map, shared with the egress rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct ingress_slot);
} wax_ingress_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct ingress_seen_key);
    __type(value, __u32); /* the generation the record was emitted under */
} wax_ingress_seen SEC(".maps");

/* bpf_d_path output is kept off the BPF stack; the hooks call policy callbacks
 * and matchers, so a 256-byte local would blow the 512-byte combined limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_path_scratch);
} wax_net_exec_path_scratch SEC(".maps");

/* Holds the extracted AF_UNIX socket path for the duration of one hook. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_path_scratch);
} wax_net_addr_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_cgroup_scratch);
} wax_net_cgroup_scratch_map SEC(".maps");

#endif /* DOOR_NET_MAPS_H */
