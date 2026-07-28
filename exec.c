// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * The execute controls: the bprm_check_security hook that decides an exec, the
 * pending-event map that carries that decision across to the commit point, and
 * the sched_process_exec tracepoint that turns it into a record.
 *
 * Included at the end of file.c rather than compiled on its own. The exec path
 * is not a separable BPF object: it runs file.c's policy engine (check), its
 * event emitter (emit_event) and its executable-path scratch map, none of which
 * a second object could reach. file.c forward-declares the two entry points it
 * calls into here — queue_exec_event and clear_pending_exec — so the dependency
 * runs one way, and by the point of inclusion everything below builds on is
 * already in scope.
 *
 * Why an allowed exec is deferred rather than emitted from the hook: the
 * record's cmdline is read from mm->arg_start..arg_end, and at bprm_check time
 * the task still carries the *invoking* image's mm, so the argv there belongs to
 * the caller rather than to the program being started. Waiting for
 * sched_process_exec, which fires once the new image is committed, is what makes
 * the cmdline the executed process's own. A denied exec never reaches that
 * tracepoint and so is emitted straight from the hook instead — see
 * check_rule_cb in file.c.
 */

/* Carries an exec decision from bprm_check_security to sched_process_exec. The
 * paths are captured at decision time because they are not recoverable at the
 * commit point: by then task->mm->exe_file is the new image, not the caller. */
struct pending_exec_event {
    __u32 uid;
    __u8 status;
    __u8 _pad[3];
    char file[PATH_LEN];
    char executable_path[PATH_LEN];
    char policy_id[POLICY_ID_LEN];
};

/* Keyed by pid. LRU rather than a plain hash because an exec that is queued but
 * never commits (the binary fails to load, the task is killed) leaves an entry
 * behind that nothing would otherwise remove. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} pending_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_exec_event);
} pending_exec_scratch SEC(".maps");

/* Drop any exec record queued for the current task but not yet committed. Each
 * exec decision supersedes the previous one for that pid, and an exec that is
 * never going to commit must not have its record emitted by a later one. */
static __always_inline void clear_pending_exec(void)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    bpf_map_delete_elem(&pending_execs, &pid);
}

static __always_inline void queue_exec_event(__u32 uid, __u8 status, const char *path,
                                             const char *policy_id)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 zero = 0;
    struct pending_exec_event *pending;
    struct executable_path_scratch *scratch;
    struct task_struct *task;
    struct task_struct *parent;
    struct mm_struct *parent_mm;
    struct file *exe_file;

    pending = bpf_map_lookup_elem(&pending_exec_scratch, &zero);
    if (!pending) return;
    pending->uid = uid;
    pending->status = status;
    bpf_probe_read_kernel_str(pending->file, sizeof(pending->file), path);
    pending->executable_path[0] = '\0';
    pending->policy_id[0] = '\0';
    if (policy_id)
        bpf_probe_read_kernel_str(pending->policy_id, sizeof(pending->policy_id),
                                  policy_id);
    scratch = bpf_map_lookup_elem(&executable_path_scratch, &zero);
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
    bpf_map_update_elem(&pending_execs, &pid, pending, BPF_ANY);
}

SEC("lsm/bprm_check_security")
long BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    if (ret) return lsm_ret(ret);
    return lsm_ret(bprm->file ? check(bprm->file, OP_EXEC) : 0);
}

SEC("tracepoint/sched/sched_process_exec")
int emit_committed_exec(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct pending_exec_event *pending;

    pending = bpf_map_lookup_elem(&pending_execs, &pid);
    if (!pending) return 0;
    emit_event(pending->uid, OP_EXEC, pending->status, pending->file,
               pending->executable_path, pending->policy_id, 1);
    bpf_map_delete_elem(&pending_execs, &pid);
    return 0;
}
