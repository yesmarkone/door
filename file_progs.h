/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/file.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from file.c:1930-2164. */
#ifndef DOOR_FILE_PROGS_H
#define DOOR_FILE_PROGS_H

/* Resolve the image about to be executed and stage it for wax_pid_image.
 *
 * Called for EVERY exec, before task_is_exempt() has a say. That is deliberate
 * and is the whole point: tasks with no audit session are the systemd-started
 * daemons — sshd, wdog, the database — and they are exactly what a kill rule
 * is written to protect. Recording only the tasks the file policy judges would
 * leave the protected set empty. */
static __always_inline void stage_exec_image(struct file *file)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32), zero = 0;
    struct file_path_scratch *ps;
    struct pid_image *img;
    long len;

    ps = bpf_map_lookup_elem(&wax_file_path_scratch, &zero);
    if (!ps) return;
    ps->path[0] = '\0';
    /* A second bpf_d_path on the exec path, since check() below resolves its
     * own and returns early for exempt tasks before it gets there. exec is
     * rare enough next to open() that unifying the two is not worth the
     * contortion it would take. */
    len = bpf_d_path(&file->f_path, ps->path, PATH_LEN);
    if (len <= 0) return;
    img = bpf_map_lookup_elem(&wax_img_scratch, &zero);
    if (!img) return;
    img->start_clock = 0;   /* filled at the tracepoint, once the exec is real */
    img->path_len = (__u32)len - 1;
    img->_pad = 0;
    bpf_probe_read_kernel_str(img->exe_path, sizeof(img->exe_path), ps->path);
    bpf_map_update_elem(&wax_pending_image, &pid, img, BPF_ANY);
}

SEC("lsm/bprm_check_security")
long BPF_PROG(wax_check_exec, struct linux_binprm *bprm, int ret)
{
    if (ret) return lsm_ret(ret);
    if (!bprm->file) return 0;
    stage_exec_image(bprm->file);
    return lsm_ret(check(bprm->file, OP_EXEC));
}

SEC("lsm/file_open")
long BPF_PROG(wax_check_open, struct file *file, int ret)
{
    __u32 mode;

    if (ret) return lsm_ret(ret);
    mode = BPF_CORE_READ(file, f_mode);
    if (mode & FMODE_WRITE) {
        ret = check(file, OP_WRITE);
        if (ret) return lsm_ret(ret);
    }
    if (mode & FMODE_READ) return lsm_ret(check(file, OP_READ));
    return 0;
}

SEC("lsm/path_unlink")
long BPF_PROG(wax_check_unlink, const struct path *dir, struct dentry *dentry)
{
    /* delete(8), not write(4). A rule carrying only the write bit does not
     * stop this. */
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_rmdir")
long BPF_PROG(wax_check_rmdir, const struct path *dir, struct dentry *dentry)
{
    /* Shares OP_UNLINK with file deletion above, so one delete rule covers both
     * and neither can be written without the other. Reported as operation 4
     * either way, which is also why a consumer cannot tell rm from rmdir. */
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_mkdir")
long BPF_PROG(wax_check_mkdir, const struct path *dir, struct dentry *dentry,
             umode_t mode)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_MKDIR));
}

SEC("lsm/path_symlink")
long BPF_PROG(wax_check_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_SYMLINK));
}

SEC("lsm/path_link")
long BPF_PROG(wax_check_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    /* Like rename, both sides are checked: hard-linking a protected file to a
     * new name must not become a way around rules on the original path. The
     * old side only provides a dentry, so it is resolved by the dentry walk. */
    int ret = check_dentry_op(old_dentry, OP_LINK);

    if (ret) return lsm_ret(ret);
    return lsm_ret(check_dir_dentry(new_dir, new_dentry, OP_LINK));
}

SEC("lsm/inode_mknod")
long BPF_PROG(wax_check_mknod, struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev)
{
    /* security_path_mknod is not in this kernel's bpf_d_path allowlist, so the
     * program attaches to inode_mknod instead and rebuilds the path from the
     * new dentry's parent chain, sharing inode_setattr's mount-prefix caveat.
     * mknod(S_IFREG) is not seen here, but regular-file creation is already
     * governed by file_open(O_CREAT). */
    return lsm_ret(check_dentry_op(dentry, OP_MKNOD));
}

SEC("lsm/path_rename")
long BPF_PROG(wax_check_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    /* Both sides are checked, with different masks. The source loses a name, so
     * it is judged as a delete; the destination gains one and may destroy what
     * was already there, so it is judged as both a write and a delete. See
     * op_perm_mask(). Either side denying blocks the rename. */
    int ret = check_dir_dentry(old_dir, old_dentry, OP_RENAME);

    if (ret) return lsm_ret(ret);
    return lsm_ret(check_dir_dentry(new_dir, new_dentry, OP_RENAME_TO));
}

SEC("lsm/path_chmod")
long BPF_PROG(wax_check_chmod, const struct path *path, umode_t mode)
{
    return lsm_ret(check_path_op(path, OP_CHMOD));
}

SEC("lsm/path_chown")
long BPF_PROG(wax_check_chown, const struct path *path)
{
    return lsm_ret(check_path_op(path, OP_CHOWN));
}

SEC("lsm/path_truncate")
long BPF_PROG(wax_check_truncate, const struct path *path)
{
    /* Path-based truncate()/truncate64() never opens the file, so
     * file_open(FMODE_WRITE) does not see it. Governing it here closes a
     * write-class bypass that would otherwise let a protected file be zeroed
     * without matching any rule. (ftruncate(fd) is already covered by
     * file_open, and O_TRUNC opens carry FMODE_WRITE there too.)
     *
     * This stays write(4) on purpose. Truncation destroys contents but leaves
     * the name, so delete(8) does not stop it — a rule that means to keep a
     * file intact, not merely present, must carry the write bit. */
    return lsm_ret(check_path_op(path, OP_TRUNCATE));
}

SEC("lsm/inode_setattr")
long BPF_PROG(wax_check_setattr, struct dentry *dentry, struct iattr *attr)
{
    __u32 ia_valid = BPF_CORE_READ(attr, ia_valid);

    /* Only explicit mtime changes (utimes/utimensat). chmod/chown pass through
     * here too but carry no MTIME bit, and size changes (ATTR_SIZE) are
     * governed by path_truncate / file_open, so they are ignored here to avoid
     * double-accounting the same write. */
    if (!(ia_valid & (ATTR_MTIME | ATTR_MTIME_SET)) || (ia_valid & ATTR_SIZE))
        return 0;
    return lsm_ret(check_dentry_op(dentry, OP_SETTIME));
}

SEC("tracepoint/sched/sched_process_exec")
int wax_emit_exec(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct pending_exec_event *pending;
    struct pid_image *staged;

    /* The exec is now real, so the image staged in bprm_check becomes this
     * process's current one. Done before the event below because it must
     * happen for every exec, and the event only fires for some. */
    staged = bpf_map_lookup_elem(&wax_pending_image, &pid);
    if (staged) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

        staged->start_clock = BPF_CORE_READ(task, start_boottime) / NSEC_PER_CLOCK;
        bpf_map_update_elem(&wax_pid_image, &pid, staged, BPF_ANY);
        bpf_map_delete_elem(&wax_pending_image, &pid);
    }

    pending = bpf_map_lookup_elem(&wax_pending_execs, &pid);
    if (!pending) return 0;
    emit_event(pending->uid, OP_EXEC, pending->status, pending->file,
               pending->executable_path, pending->policy_id, 1, 0, 0,
               pending->rule_slot);
    bpf_map_delete_elem(&wax_pending_execs, &pid);
    return 0;
}

/* A process that forks without ever calling exec keeps running its parent's
 * image — a subshell of /bin/bash is still /bin/bash. Without this the child
 * would have no entry at all and would match no target_path rule, which for a
 * deny rule means the protection silently does not apply to it. */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(wax_track_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 ppid = BPF_CORE_READ(parent, tgid), cpid = BPF_CORE_READ(child, tgid);
    __u32 zero = 0;
    struct pid_image *pimg, *copy;

    if (ppid == cpid) return 0;         /* a new thread, not a new process */
    pimg = bpf_map_lookup_elem(&wax_pid_image, &ppid);
    if (!pimg) return 0;
    /* Copied through scratch rather than edited in place: pimg points into the
     * parent's map value, and stamping the child's start time onto it would
     * corrupt the parent's entry and make it fail its own staleness check. */
    copy = bpf_map_lookup_elem(&wax_img_scratch, &zero);
    if (!copy) return 0;
    __builtin_memcpy(copy, pimg, sizeof(*copy));
    /* The child gets its own start time: the entry must stay verifiable
     * against the task it now describes, not the one it was copied from. */
    copy->start_clock = BPF_CORE_READ(child, start_boottime) / NSEC_PER_CLOCK;
    bpf_map_update_elem(&wax_pid_image, &cpid, copy, BPF_ANY);
    return 0;
}

/* Drop the entry when the process is gone. The LRU would eventually reclaim it
 * and start_clock would catch a reused pid regardless, but neither is a reason
 * to leave the table full of the dead. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(wax_track_exit, struct task_struct *task)
{
    __u32 pid = BPF_CORE_READ(task, pid), tgid = BPF_CORE_READ(task, tgid);

    if (pid != tgid) return 0;          /* a thread exiting, not the process */
    bpf_map_delete_elem(&wax_pid_image, &tgid);
    bpf_map_delete_elem(&wax_pending_image, &tgid);
    return 0;
}
#endif /* DOOR_FILE_PROGS_H */
