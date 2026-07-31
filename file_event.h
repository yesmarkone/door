/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:932-1061. */
#ifndef DOOR_FILE_EVENT_H
#define DOOR_FILE_EVENT_H

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
                                       __u8 signal, const struct cred_event_ids *ids,
                                       __u32 rule_slot)
{
    struct event *e = bpf_ringbuf_reserve(&wax_events, sizeof(*e), 0);
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
    e->rule_slot = rule_slot;
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
                                             const char *policy_id, __u32 rule_slot)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 zero = 0;
    struct pending_exec_event *pending;
    struct executable_path_scratch *scratch;
    struct task_struct *task;
    struct task_struct *parent;
    struct mm_struct *parent_mm;
    struct file *exe_file;

    pending = bpf_map_lookup_elem(&wax_exec_scratch, &zero);
    if (!pending) return;
    pending->uid = uid;
    pending->status = status;
    pending->rule_slot = rule_slot;
    bpf_probe_read_kernel_str(pending->file, sizeof(pending->file), path);
    pending->executable_path[0] = '\0';
    pending->policy_id[0] = '\0';
    if (policy_id)
        bpf_probe_read_kernel_str(pending->policy_id, sizeof(pending->policy_id),
                                  policy_id);
    scratch = bpf_map_lookup_elem(&wax_executable_path_scratch, &zero);
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
    bpf_map_update_elem(&wax_pending_execs, &pid, pending, BPF_ANY);
}

#endif /* DOOR_FILE_EVENT_H */
