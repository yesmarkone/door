/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:496-672, before the split. */
#ifndef DOOR_FILE_MAPS_H
#define DOOR_FILE_MAPS_H

/*
 * Not dead code; door/net_maps.h carries the same three lines and the full
 * explanation. In short: with a global (non-inlined) subprogram in the object —
 * check_policy and check_policy_walk in door/file_policy.h — clang emits these
 * slot types into BTF as forward declarations only, and libbpf then cannot size
 * the inner maps of the map-in-maps below ("can't determine value size for type
 * [N]: -22"). A global variable of each type forces the layout back out. It is a
 * toolchain behaviour rather than a kernel one, so an older build host does not
 * escape it either.
 */
struct policy_slot __wax_force_policy_slot_btf;
struct proc_policy_slot __wax_force_proc_slot_btf;
struct cred_policy_slot __wax_force_cred_slot_btf;

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct policy_slot);
} wax_policy_template SEC(".maps");

/* Keyed by (login uid, employee id), not by uid alone: one shared account can
 * carry a different policy per person. See struct policy_key in file_types.h
 * for the lookup order and what it means that an employee-scoped policy
 * replaces the unscoped one instead of layering over it.
 *
 * The name still says by_uid. It is the pin name, the Go constant, the string
 * in the SELinux module and in half the documentation; renaming it would cost
 * all of that to say something the key type already says. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    /* Entries are (uid, person) pairs now, not uids, so the old 4096 would be
     * spent by a few hundred shared accounts. */
    __uint(max_entries, 16384);
    __type(key, struct policy_key);
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
    __uint(max_entries, 16384);
    __type(key, struct policy_key);  /* see wax_active_policy_by_uid */
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
    __uint(max_entries, 16384);
    __type(key, struct policy_key);  /* see wax_active_policy_by_uid */
    __array(values, typeof(wax_cred_policy_template));
} wax_active_cred_policy_by_uid SEC(".maps");

/* The login uids that have a policy of their own — the set the host fallback
 * policy at FALLBACK_UID does NOT cover.
 *
 * Keyed by uid alone, deliberately, while the policy maps above are keyed by
 * (uid, employee). The question here is "does this uid have any policy at all",
 * and it has to stay that: a uid whose only policies name individual employees
 * is still a managed uid, and the person who logs in unnamed must get that
 * uid's own default — allow, or whatever its unscoped policy says — rather than
 * the host fallback meant for uids nobody enumerated.
 *
 * It exists because "no inner map" does not mean "no policy" for three of the
 * four spaces. wdog creates a proc, cred or net inner map only when the policy
 * carries rules of that kind, so a policy with fileRules alone leaves
 * wax_active_proc_policy_by_uid empty for its uid. Falling back on that
 * emptiness would hand that user the fallback's procRules, and the fallback is
 * a per-uid decision rather than a per-rule-kind one: a uid with a policy is
 * out of the fallback's reach in every space, including the ones its own policy
 * says nothing about. Leaving procRules out is an operator saying "this uid's
 * kill and ptrace are ungoverned", and a host-wide default must not quietly
 * overrule it.
 *
 * THE VALUE IS A PRESENCE FLAG AND MUST NOT BECOME A PER-SPACE BITMASK. A mask
 * would reintroduce exactly the chaining the paragraph above rejects.
 *
 * Deliberately NOT pinned, unlike wax_session_identity and wax_employee_ids
 * below. Those two must outlive wdog; this one must not. A stale pin claiming a
 * uid is managed, read by a restarted wdog that has not yet replayed its
 * policies, would exempt that uid from the fallback during exactly the window
 * the fallback exists to cover. Not pinning is also why net.c declares its own
 * copy rather than sharing this one — the same split, and for the same reason,
 * as wax_runtime_config_map and wax_net_runtime_config_map. wdog writes both
 * from one source. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);  /* the bound the outer policy maps already have */
    __type(key, __u32);         /* login uid */
    __type(value, __u8);        /* always 1; see above */
} wax_managed_uids SEC(".maps");

/* The fallback policy's load-time gate. Written by the loader with
 * CollectionSpec.RewriteConstants before the collection is built, exactly like
 * door/self_maps.h's constants, so the verifier folds it to an immediate and
 * dead-code eliminates every branch it guards. With --fallback-policy=off the
 * entry functions verify as the byte-identical programs they were before this
 * feature existed.
 *
 * That retreat is not decoration. The rule loop below these branches carries two
 * nested glob matchers, and a state split ahead of it once put wax_check_sendmsg
 * in net.c past the verifier's million-instruction ceiling outright — the object
 * stopped loading. This feature is believed not to split that state (both
 * lookups hit one outer map, so the two arms carry one inner_map_meta and merge),
 * but "believed" is what the gate is for. */
volatile const __u8 wax_fallback_on = 0;

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
 * only (pam_wood.so on login/logout, wdog's reaper once a session's last process
 * is gone), read here on every check.
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
 * ceasing to match and nothing in the log but a PAM warning.
 *
 * At 176 bytes an entry that costs about 11.5MB of values (5.2MB before the
 * session origin axis added service and rhost, 80 -> 176 bytes), all of it
 * preallocated — a plain hash without BPF_F_NO_PREALLOC pays at load whether
 * anyone is logged in or not. `bpftool map show` reports 16.2MB of memlock, the
 * rest being the bucket array and per-element overhead. Halving max_entries
 * would buy that back and give up the bound above; the bound is worth more.
 *
 * Changing max_entries — or the value size, which the origin axis did — changes
 * the pinned map's shape, so checkPin (cmd/wdog/session.go) refuses to start
 * against a pin left by an older build. That refusal is correct and its message
 * already carries the remedy; see the upgrade note in docs/deploy.md. Note what
 * that remedy costs here: removing the pin discards the records of sessions
 * that are still logged in, and they read as ORIGIN_UNKNOWN with no employee
 * until their next login. */
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
