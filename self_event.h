/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_EVENT_H
#define DOOR_SELF_EVENT_H

/* bpf_ringbuf_reserve hands back uninitialized memory and clang will not inline
 * a memset for the BPF target, so the record is cleared with an unrolled word
 * loop — the same shape as zero_event() in door/file_event.h, over eight words
 * instead of a hundred and eighty. */
static __always_inline void zero_self_event(struct self_event *e)
{
    volatile __u64 *p = (volatile __u64 *)e;

#pragma unroll
    for (int i = 0; i < sizeof(*e) / 8; i++)
        p[i] = 0;
}

/* There is no no_event mask here and there will not be one.
 *
 * The policy engine has one (struct rule::no_event_s / no_event_fw) because an
 * operator writing a broad allow rule needs a way to stop it flooding the log,
 * and warnNoEventHidesWarn (cmd/wdog/main.go) exists to catch the one
 * combination where that suppression makes a rule neither deny nor report.
 * This layer has no such combination available to it: silence is not a state it
 * can be in. Agent's --event-filter is bypassed for the same reason.
 *
 * With ONE exception, and it is worth knowing before reading the paragraph above
 * as an absolute. SOP_LOGIN and SOP_LOGOUT ride this same ring but are not
 * self-defense — they observe rather than refuse — so they fall outside
 * model.Operation.IsSelfDefense() and the filter CAN hide them. Everything on
 * this ring that denied something is still unsuppressible, including the
 * SOP_BPF_MAP line self_session_record raises when a login looks forged. */
static __always_inline void emit_self_event(__u8 op, __u8 kind, __u8 status,
                                            __u32 dev, __u64 ino, __u32 target,
                                            __u8 detail)
{
    struct self_event *e = bpf_ringbuf_reserve(&wax_self_events, sizeof(*e), 0);
    struct task_struct *task, *parent;

    if (!e) return;
    zero_self_event(e);
    e->timestamp_ns = bpf_ktime_get_ns();
    e->ino = ino;
    e->dev = dev;
    e->target = target;
    e->op = op;
    e->status = status;
    e->kind = kind;
    e->detail = detail;
    e->real_uid = (__u32)bpf_get_current_uid_gid();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    task = (struct task_struct *)bpf_get_current_task_btf();
    /* The login uid, exactly as every other event in this system reports it —
     * so a self-defense denial joins the same audit trail the policy events
     * are read on, and `--event-filter uid=...` keeps working across both. */
    e->uid = BPF_CORE_READ(task, loginuid.val);
    e->session_id = BPF_CORE_READ(task, sessionid);
    parent = task->real_parent;
    if (parent)
        e->ppid = parent->tgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

#endif /* DOOR_SELF_EVENT_H */
