/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:874-954, before the split. */
#ifndef DOOR_NET_EVENT_H
#define DOOR_NET_EVENT_H

/* bpf_ringbuf_reserve hands back uninitialized memory, and clang refuses to
 * inline a memset this large for the BPF target, so clear the record with an
 * unrolled word loop. sizeof(struct net_event) is a multiple of 8 and
 * ring-buffer memory is 8-byte aligned. */
static __always_inline void zero_net_event(struct net_event *e)
{
    volatile __u64 *p = (volatile __u64 *)e;

#pragma unroll
    for (int i = 0; i < sizeof(*e) / 8; i++)
        p[i] = 0;
}

static __always_inline void emit_net_event(__u32 uid, __u8 op, __u8 status,
                                           const struct net_target *t,
                                           const char *executable_path,
                                           const char *policy_id, __u32 rule_slot)
{
    struct net_event *e = bpf_ringbuf_reserve(&wax_net_events, sizeof(*e), 0);
    struct task_struct *task;
    struct tty_struct *tty = 0;
    struct mm_struct *mm = 0;
    unsigned long arg_start = 0, arg_end = 0;
    __u32 cmdline_len = 0;

    if (!e) return;
    /* Zero up front so the fixed-size string fields and the struct padding
     * never carry stale ring-buffer bytes past their NUL into userspace. */
    zero_net_event(e);
    e->uid = uid;
    e->real_uid = (__u32)bpf_get_current_uid_gid();
    e->operation = op;
    e->status = status;
    e->rule_slot = rule_slot;
    e->create_timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->family = t->family;
    e->protocol = t->protocol;
    e->sock_type = t->sock_type;
    e->addr_valid = t->has_addr;
    if (t->is_remote) {
        e->remote_port = t->port;
        __builtin_memcpy(e->remote_addr, t->addr, 16);
    } else {
        e->local_port = t->port;
        __builtin_memcpy(e->local_addr, t->addr, 16);
    }
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
    if (mm) {
        BPF_CORE_READ_INTO(&arg_start, mm, arg_start);
        BPF_CORE_READ_INTO(&arg_end, mm, arg_end);
        if (arg_end > arg_start) {
            unsigned long arg_len = arg_end - arg_start;

            cmdline_len = arg_len > CMDLINE_LEN ? CMDLINE_LEN : (__u32)arg_len;
            if (bpf_probe_read_user(e->cmdline, cmdline_len, (void *)arg_start) == 0)
                e->cmdline_len = cmdline_len;
        }
    }
    if (t->path)
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), t->path);
    if (executable_path)
        bpf_probe_read_kernel_str(e->executable_path, sizeof(e->executable_path),
                                  executable_path);
    if (policy_id)
        bpf_probe_read_kernel_str(e->policy_id, sizeof(e->policy_id), policy_id);
    bpf_ringbuf_submit(e, 0);
}

#endif /* DOOR_NET_EVENT_H */
