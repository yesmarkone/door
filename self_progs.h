/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/self.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. */
#ifndef DOOR_SELF_PROGS_H
#define DOOR_SELF_PROGS_H

/* ===========================================================================
 * Signals and ptrace — protecting the two processes.
 * =========================================================================== */

SEC("lsm/task_kill")
long BPF_PROG(wax_self_kill, struct task_struct *p, struct kernel_siginfo *info,
              int sig, const struct cred *cred)
{
    __u32 target;
    struct self_task_val *t;

    if (self_disarmed()) return 0;
    target = BPF_CORE_READ(p, tgid);
    t = bpf_map_lookup_elem(&wax_self_tasks, &target);
    if (!t) return 0; /* not one of ours, so not our business */
    if (self_trusted()) return 0;
    /* PID 1 is the documented escape hatch, and the ONLY signal path this layer
     * leaves open by default: `systemctl stop wagent` has to keep working,
     * which is what docs/rules-process.md has always promised. --self-kill=strict
     * closes it, and then the way out is the signed unseal or a reboot — the
     * latter works regardless, because reboot(2) is not a signal.
     *
     * Note this is checked AFTER self_trusted(): PID 1 is not in the trust set,
     * because trusting init for map access would be a much larger grant than
     * letting it stop the service. */
    if (self_cfg_flag(SCFG_KILL_ALLOW_PID1) &&
        (__u32)(bpf_get_current_pid_tgid() >> 32) == 1)
        return 0;
    /* SIGSTOP is denied along with the rest, and not because it drops
     * enforcement — it does not, the LSM programs keep running with wdog frozen
     * — but because a stopped wdog stops draining the ring buffers, and the
     * events that go missing are the ones describing whatever happens next. */
    return lsm_ret(self_deny(SOP_KILL, (__u8)t->role, 0, 0, target, (__u8)sig));
}

SEC("lsm/ptrace_access_check")
long BPF_PROG(wax_self_ptrace, struct task_struct *child, unsigned int mode)
{
    __u32 target;
    struct self_task_val *t;

    if (self_disarmed()) return 0;
    target = BPF_CORE_READ(child, tgid);
    t = bpf_map_lookup_elem(&wax_self_tasks, &target);
    if (!t) return 0;
    if (self_trusted()) return 0;
    /* This is worth more than it looks. The kernel routes /proc/<pid>/mem,
     * /proc/<pid>/environ AND /proc/<pid>/fd/N through here
     * (proc_fd_access_allowed -> ptrace_may_access), so one deny closes three
     * doors at once: patching wdog's memory, reading its secrets, and
     * re-opening its BPF map file descriptors. That last one bypasses
     * security_bpf_map() entirely — nothing in wax_self_bpf_map below can see
     * it — so this program is not a duplicate of that one, it is the other
     * half of it. */
    return lsm_ret(self_deny(SOP_PTRACE, (__u8)t->role, 0, 0, target,
                             (__u8)(mode & 3)));
}

/* ===========================================================================
 * The BPF subsystem — the maps and programs this whole system is made of.
 * =========================================================================== */

/* Both routes to a map — BPF_MAP_GET_FD_BY_ID (what `bpftool map update id N`
 * uses) and BPF_OBJ_GET (what opening a pin uses) — funnel through
 * bpf_map_new_fd(), which is where this hook fires. One program covers both.
 *
 * Identification is the four-byte name prefix rather than a set of map ids, and
 * that is not a micro-optimisation. The inner policy maps are created and
 * closed on EVERY ReplacePolicies (cmd/wdog/main.go), so an id set would need
 * updating on every apply, would have a window between ebpf.NewMap and the
 * guard learning the id, and would have a second window where a freed id is
 * reassigned to a stranger's map while still marked protected. A name prefix
 * has none of those: one u32 compare, inner maps covered automatically because
 * they inherit wax_policy_template's name, and nothing to keep in sync. */
SEC("lsm/bpf_map")
long BPF_PROG(wax_self_bpf_map, struct bpf_map *map, fmode_t fmode)
{
    char name[16];
    __u32 pfx;
    __u64 pfx8;

    if (self_disarmed() || !self_map_prefix) return 0;
    bpf_core_read(name, sizeof(name), &map->name);
    __builtin_memcpy(&pfx, name, 4);
    if (pfx != self_map_prefix) return 0; /* not ours; not our business */
    if (self_trusted()) return 0;

    /* THE ONE EXCEPTION, stated rather than hidden.
     *
     * pam_wood.so opens this map's pin with BPF_OBJ_GET on every login and
     * writes it (pam/pam.c). Not talking to wdog is the point of that design —
     * a login has to be recordable while wdog is down — so sealing this would
     * make every SSH session depend on this daemon being up. The cost is that a
     * root attacker can forge or erase employee identity, which mis-scopes
     * employeeName rules; rules naming nobody are unaffected. See
     * docs/self-defense.md, "known gaps".
     *
     * It is the only access this layer permits, so it is the only access that
     * needs watching: every non-trusted open is reported. PAM produces one per
     * login, which is a low enough baseline that a burst is visible.
     *
     * The event stays even though wax_self_bpf now names the command that
     * follows, and it has to. An open that issues no recognized command —
     * `bpftool map dump` reading every employee name on the host — would
     * otherwise produce nothing at all, and that coverage is the entire
     * justification for permitting the exception. The cost is a second line per
     * login, which at a few logins an hour is not a volume anyone will notice. */
    __builtin_memcpy(&pfx8, name, 8);
    if (pfx8 == self_session_map_prefix) {
        __u64 tid = bpf_get_current_pid_tgid();
        struct self_pin_open o = {};

        /* Remember the fd so the next map command from this thread can be named.
         * A full or evicting map costs a MISSING login event, never a wrong one:
         * nothing downstream invents a session out of an absent entry. */
        o.at_ns = bpf_ktime_get_ns();
        o.map_id = BPF_CORE_READ(map, id);
        bpf_map_update_elem(&wax_self_pin_opens, &tid, &o, BPF_ANY);
        emit_self_event(SOP_BPF_MAP, SKIND_PIN, 'W', 0, 0, o.map_id,
                        (__u8)fmode);
        return 0;
    }
    return lsm_ret(self_deny(SOP_BPF_MAP, SKIND_MAP, 0, 0,
                             BPF_CORE_READ(map, id), (__u8)fmode));
}

SEC("lsm/bpf_prog")
long BPF_PROG(wax_self_bpf_prog, struct bpf_prog *prog)
{
    char name[16];
    __u32 pfx;

    if (self_disarmed() || !self_map_prefix) return 0;
    bpf_core_read(name, sizeof(name), &prog->aux->name);
    __builtin_memcpy(&pfx, name, 4);
    if (pfx != self_map_prefix) return 0;
    if (self_trusted()) return 0;
    return lsm_ret(self_deny(SOP_BPF_PROG, SKIND_PROG, 0, 0,
                             BPF_CORE_READ(prog, aux, id), 0));
}

/* The cmd-level hook, which exists for two things the two above cannot see.
 *
 * LINKS: bpf_link_new_fd() calls anon_inode_getfd() directly — there is no
 * security_bpf_link() in this kernel — so a link fd can only be gated here.
 *
 * And the ATTR, which is what separates a login from a logout: both arrive at
 * wax_self_bpf_map as the identical fd on the identical map, and nothing there
 * tells them apart. It used to be the command alone — update versus delete —
 * but close_session now updates the record to mark it closed rather than
 * deleting it, so the two commands no longer line up with the two events. The
 * update flag does; self_session_record() explains why that signal is honest and
 * why delete is still read as a logout. */
SEC("lsm/bpf")
long BPF_PROG(wax_self_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (self_disarmed()) return 0;

    /* First, because these two commands are the hot ones on this host: wdog
     * issues thousands of BPF_MAP_UPDATE_ELEM on every ReplacePolicies. It pays
     * one lookup in the 16-entry wax_self_tasks and stops — the same lookup
     * wax_self_kill already makes for every signal sent anywhere on the system.
     *
     * self_trusted() before the scratch lookup rather than after is also a proof
     * obligation, not a preference: it is what makes it structurally impossible
     * for wdog's OWN session-map delete — the reaper collecting a dead session,
     * cmd/wdog/session.go — to be reported as a logout. That reaper emits its
     * own event, and this is the half that keeps the two from doubling up. */
    if (cmd == BPF_MAP_UPDATE_ELEM || cmd == BPF_MAP_DELETE_ELEM) {
        if (!self_session_map_prefix) return 0; /* .rodata; folded away */
        if (self_trusted()) return 0;
        self_session_record(cmd, attr);
        return 0;
    }

    /* Trampoline-slot squatting. A BPF LSM hook holds a bounded number of
     * programs, so an attacker who fills bpf_lsm_file_open with dummies before
     * wdog starts makes AttachLSM fail with -E2BIG — not a bypass but, with a
     * supervisor restarting wdog, a permanent denial of service. This object
     * attaches roughly forty-five seconds before the file and network objects
     * do, so guarding here is what protects THEIR attach.
     *
     * Narrowed to BPF_LSM_MAC deliberately: gating BPF_LINK_CREATE at large
     * would break every other BPF user on the host, and nobody but wdog
     * attaches an LSM program here. */
    if (cmd == BPF_LINK_CREATE) {
        if (!self_cfg_flag(SCFG_BPF_LINK_GUARD)) return 0;
        if (BPF_CORE_READ(attr, link_create.attach_type) != BPF_LSM_MAC)
            return 0;
        if (self_trusted()) return 0;
        return lsm_ret(self_deny(SOP_BPF, SKIND_LINK, 0, 0, (__u32)cmd, 0));
    }
    /* Off by default; see SCFG_BPF_LINK_STRICT. BPF_PROG_DETACH is deliberately
     * NOT in this list: it cannot reach a tracing link, and systemd uses it for
     * cgroup device and IP policies on every unit stop. */
    if (cmd == BPF_LINK_DETACH || cmd == BPF_LINK_GET_FD_BY_ID) {
        if (!self_cfg_flag(SCFG_BPF_LINK_STRICT)) return 0;
        if (self_trusted()) return 0;
        return lsm_ret(self_deny(SOP_BPF, SKIND_LINK, 0, 0, (__u32)cmd, 0));
    }
    return 0;
}

/* ===========================================================================
 * Files, by identity.
 * =========================================================================== */

SEC("lsm/file_open")
long BPF_PROG(wax_self_open, struct file *file, int ret)
{
    struct inode *inode;
    struct dentry *dentry;
    __u32 mode, dev, imode, rdev, *rf;

    if (ret) return lsm_ret(ret);
    if (self_disarmed()) return 0;
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return 0;
    mode = BPF_CORE_READ(file, f_mode);
    dev = BPF_CORE_READ(inode, i_sb, s_dev);
    dentry = BPF_CORE_READ(file, f_path.dentry);

    /* CONFIG_AUDIT_LOGINUID_IMMUTABLE, implemented in BPF because RHEL 9's
     * stock kernel does not set it (verified on 5.14.0-503.14.1.el9_5).
     *
     * Without it, root can rewrite /proc/self/loginuid — and the kernel's
     * audit_set_loginuid() clears sessionid along with it, so writing the unset
     * value does two things at once: check_policy loses the key it selects a
     * policy with (door/file_policy.h:147, and an absent policy is a silent
     * allow), and task_is_exempt() starts returning true (door/file_policy.h:111),
     * which waves the task past all twenty-three policy hooks. One echo.
     *
     * This reproduces the kernel option's own semantics rather than banning the
     * write outright: pam_loginuid.so performs it legitimately on every login,
     * and at that moment the login daemon's own loginuid is still unset. A task
     * whose loginuid is ALREADY set has no business changing it.
     * proc_loginuid_write() refuses `current != task`, so there is no
     * /proc/<other>/loginuid variant to cover.
     *
     * The cost on the hottest hook in the system is a compare against a
     * .rodata immediate: writes to procfs are rare, and a read never reaches
     * the second clause. */
    if ((mode & FMODE_WRITE) && self_proc_dev && dev == self_proc_dev &&
        self_name_is_loginuid(dentry)) {
        struct task_struct *task =
            (struct task_struct *)bpf_get_current_task_btf();

        if (BPF_CORE_READ(task, loginuid.val) != (__u32)-1 && !self_trusted())
            return lsm_ret(self_deny(SOP_LOGINUID, SKIND_LOGINUID, dev,
                                     BPF_CORE_READ(inode, i_ino), 0, 0));
    }

    /* Device nodes are named by the driver they address, not by their inode: an
     * attacker who cannot touch /dev/mem can mknod their own, and it is a
     * different inode on a different filesystem. i_rdev is the part that does
     * not change. Gated behind the file-type test so an ordinary open never
     * pays for the lookup. */
    imode = BPF_CORE_READ(inode, i_mode);
    if ((imode & S_IFMT) == S_IFCHR || (imode & S_IFMT) == S_IFBLK) {
        rdev = BPF_CORE_READ(inode, i_rdev);
        rf = bpf_map_lookup_elem(&wax_self_rdevs, &rdev);
        if (rf && (*rf & ((mode & FMODE_WRITE) ? SELF_NO_WRITE : SELF_NO_READ)) &&
            !self_trusted())
            return lsm_ret(self_deny(SOP_RDEV, SKIND_DEVICE, 0, rdev, 0,
                                     (__u8)mode));
    }

    if (mode & FMODE_WRITE)
        return lsm_ret(self_guard(inode, dentry, SELF_NO_WRITE, SOP_WRITE, 0));
    /* A read open costs one ARRAY lookup and a bit test when no protected
     * object asks to be unreadable — which is the normal configuration, since
     * reading a binary is not a way around anything. Only /proc/kcore and the
     * /dev/mem class carry SELF_NO_READ. */
    if (!self_cfg_flag(SCFG_HAVE_READ_GUARD)) return 0;
    return lsm_ret(self_guard(inode, dentry, SELF_NO_READ, SOP_READ, 0));
}

/* Listing one of the daemon's own directories: getdents(2)/getdents64(2), judged
 * where iterate_dir() calls security_file_permission(file, MAY_READ).
 *
 * Enumeration is not modification, so this is the one self-defense control that
 * is about disclosure rather than integrity. It is worth being precise about
 * what it buys: the pin NAMES are public by construction (they are in
 * pinnedMapNames, in docs/deploy.md, and in `bpftool map show`), so this is not
 * secrecy. What it removes is the reconnaissance step — an attacker enumerating
 * the store directory to learn which files exist before trying to swap one, and
 * doing it without tripping a single event.
 *
 * ORDER MATTERS HERE MORE THAN ANYWHERE ELSE IN THIS OBJECT. self.c attaches
 * ~45s before the file object and runs on every host, and file_permission is
 * called on every read() and every write() of every regular file and socket. The
 * directory test comes first because it is two loads and a compare, then the
 * config flag, which is an ARRAY lookup and is clear on any host with no
 * list-guarded entry. Only past both does anything touch the inode hash.
 *
 * Unlike the file object's readdir hook this needs no path at all: self-defense
 * matches on {dev, ino}, which is why bpf_d_path being unavailable at this
 * attach point (see door/file_walk.h) costs this program nothing. */
SEC("lsm/file_permission")
long BPF_PROG(wax_self_readdir, struct file *file, int mask, int ret)
{
    struct inode *inode;
    __u32 imode;

    if (ret) return lsm_ret(ret);
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return 0;
    imode = BPF_CORE_READ(inode, i_mode);
    if ((imode & S_IFMT) != S_IFDIR) return 0;   /* the hot-path early-out */
    if (!(mask & MAY_READ)) return 0;
    if (!self_cfg_flag(SCFG_HAVE_LIST_GUARD)) return 0;
    /* No f_pos gate, unlike the file object's hook. Self-defense denies rather
     * than reports, and a refusal that only lands on the first getdents of a
     * pass would not be a refusal. Its event volume is bounded by the deny
     * itself: the caller does not get a second batch. */
    return lsm_ret(self_guard(inode, BPF_CORE_READ(file, f_path.dentry),
                              SELF_NO_LIST, SOP_READDIR, 0));
}

SEC("lsm/path_unlink")
long BPF_PROG(wax_self_unlink, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(self_guard_dir_dentry(dir, dentry, SELF_NO_UNLINK,
                                         SOP_UNLINK));
}

SEC("lsm/path_rmdir")
long BPF_PROG(wax_self_rmdir, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(self_guard_dir_dentry(dir, dentry, SELF_NO_UNLINK,
                                         SOP_UNLINK));
}

SEC("lsm/path_rename")
long BPF_PROG(wax_self_rename, const struct path *old_dir,
              struct dentry *old_dentry, const struct path *new_dir,
              struct dentry *new_dentry)
{
    /* The source loses a name, so it is judged as a removal. The destination
     * gains one and may destroy what is already there, so it is judged as both.
     * Either side denying blocks the rename — the same split door/file_progs.h
     * makes for the policy engine, for the same reason.
     *
     * new_dentry->d_inode is NULL when the destination name does not exist yet,
     * which is the common case; self_guard_dir_dentry falls through to the
     * parent directory test, and that is what stops a replacement being renamed
     * into a protected directory. */
    long r = self_guard_dir_dentry(old_dir, old_dentry, SELF_NO_UNLINK,
                                   SOP_UNLINK);

    if (r) return lsm_ret(r);
    return lsm_ret(self_guard_dir_dentry(new_dir, new_dentry,
                                         SELF_NO_WRITE | SELF_NO_UNLINK,
                                         SOP_CREATE));
}

SEC("lsm/path_link")
long BPF_PROG(wax_self_link, struct dentry *old_dentry,
              const struct path *new_dir, struct dentry *new_dentry)
{
    /* A second name for a protected inode is a second write path to it, and
     * unlike the policy engine this layer cannot be fooled by which one is
     * used — both names resolve to the same {dev,ino}. Refusing the link is
     * still worth it: it keeps the protected set small enough to reason about. */
    long r = self_guard_dentry(old_dentry, SELF_NO_WRITE, SOP_CREATE);

    if (r) return lsm_ret(r);
    return lsm_ret(self_guard_parent(BPF_CORE_READ(new_dir, dentry),
                                     SELF_NO_WRITE, SOP_CREATE));
}

SEC("lsm/path_symlink")
long BPF_PROG(wax_self_symlink, const struct path *dir, struct dentry *dentry,
              const char *old_name)
{
    return lsm_ret(self_guard_parent(BPF_CORE_READ(dir, dentry), SELF_NO_WRITE,
                                     SOP_CREATE));
}

SEC("lsm/path_mkdir")
long BPF_PROG(wax_self_mkdir, const struct path *dir, struct dentry *dentry,
              umode_t mode)
{
    return lsm_ret(self_guard_parent(BPF_CORE_READ(dir, dentry), SELF_NO_WRITE,
                                     SOP_CREATE));
}

/* path_mknod, and NOT inode_mknod — the difference is load-bearing here.
 *
 * bpf_obj_do_pin() calls security_path_mknod() and never reaches vfs_mknod(),
 * so security_inode_mknod() is not called for a BPF pin at all. The policy
 * engine attaches to inode_mknod (door/file_progs.h:107) and therefore cannot
 * see a pin being created. That is the second half of an attack whose first
 * half is deleting the real one: plant a decoy map at
 * /sys/fs/bpf/wax/wax_session_identity with matching geometry, and
 * pam_wood.so writes identities into it while wdog reads the real map — or,
 * after a wdog restart, LIBBPF_PIN_BY_NAME attaches wdog to the attacker's map
 * and checkPin's geometry comparison passes it silently (cmd/wdog/session.go).
 *
 * The policy engine avoided this hook because it is not in this kernel's
 * bpf_d_path allowlist (door/file_progs.h:111). This object never calls
 * bpf_d_path, so that constraint does not apply — only attachability does, and
 * that was verified before any of this was written.
 *
 * This also covers AF_UNIX bind(2) for the socket directory, the same way
 * inode_mknod does for the policy engine. */
SEC("lsm/path_mknod")
long BPF_PROG(wax_self_mknod, const struct path *dir, struct dentry *dentry,
              umode_t mode, unsigned int dev)
{
    return lsm_ret(self_guard_parent(BPF_CORE_READ(dir, dentry), SELF_NO_WRITE,
                                     SOP_CREATE));
}

SEC("lsm/path_truncate")
long BPF_PROG(wax_self_truncate, const struct path *path)
{
    return lsm_ret(self_guard_dentry(BPF_CORE_READ(path, dentry),
                                     SELF_NO_WRITE, SOP_WRITE));
}

SEC("lsm/path_chmod")
long BPF_PROG(wax_self_chmod, const struct path *path, umode_t mode)
{
    return lsm_ret(self_guard_dentry(BPF_CORE_READ(path, dentry),
                                     SELF_NO_WRITE, SOP_WRITE));
}

SEC("lsm/path_chown")
long BPF_PROG(wax_self_chown, const struct path *path, uid_t uid, gid_t gid)
{
    return lsm_ret(self_guard_dentry(BPF_CORE_READ(path, dentry),
                                     SELF_NO_WRITE, SOP_WRITE));
}

SEC("lsm/inode_setattr")
long BPF_PROG(wax_self_setattr, struct dentry *dentry, struct iattr *attr)
{
    return lsm_ret(self_guard_dentry(dentry, SELF_NO_WRITE, SOP_WRITE));
}

/* ===========================================================================
 * Mounts — the shadowing attacks that defeat every path-based rule.
 * =========================================================================== */

SEC("lsm/sb_mount")
long BPF_PROG(wax_self_mount, const char *dev_name, const struct path *path,
              const char *type, unsigned long flags, void *data)
{
    /* `mount --bind /tmp/evil /usr/sbin/wdog` hides the binary; so does the same
     * over /usr/sbin, and that costs the attacker one word less. The loader
     * therefore publishes every protected object's ancestor directories with
     * SELF_NO_MOUNT of their own, and that is what covers the second form.
     *
     * So the mount point is judged BY ITSELF, with no walk toward the root. The
     * walk would answer a different question — "is this somewhere inside a
     * protected directory" — and every mount under /run or on the root
     * filesystem answers it yes. See self_ancestor_applies (door/self_check.h)
     * for what that cost before it was taken out. */
    struct dentry *d = BPF_CORE_READ(path, dentry);

    return lsm_ret(self_guard(BPF_CORE_READ(d, d_inode), d, SELF_NO_MOUNT,
                              SOP_MOUNT, 0));
}

SEC("lsm/move_mount")
long BPF_PROG(wax_self_move_mount, const struct path *from_path,
              const struct path *to_path)
{
    /* Destination only, and judged by itself for the same reason as sb_mount. */
    struct dentry *d = BPF_CORE_READ(to_path, dentry);

    return lsm_ret(self_guard(BPF_CORE_READ(d, d_inode), d, SELF_NO_MOUNT,
                              SOP_MOUNT, 0));
}

SEC("lsm/sb_umount")
long BPF_PROG(wax_self_umount, struct vfsmount *mnt, int flags)
{
    __u32 dev, *f;
    struct dentry *root;

    if (self_disarmed()) return 0;
    /* Keyed on the superblock rather than on an inode, because what is being
     * removed is the whole filesystem. Unmounting bpffs takes the pins with it,
     * which stops pam_wood.so finding wax_session_identity — and the only trace
     * of that is a PAM warning whose text ("is wdog running?") is
     * indistinguishable from the benign case. */
    dev = BPF_CORE_READ(mnt, mnt_sb, s_dev);
    f = bpf_map_lookup_elem(&wax_self_devs, &dev);
    if (f && (*f & SELF_NO_UMOUNT)) {
        if (self_trusted()) return 0;
        return lsm_ret(self_deny(SOP_UMOUNT, SKIND_ANY, dev, 0, 0, (__u8)flags));
    }
    root = BPF_CORE_READ(mnt, mnt_root);
    return lsm_ret(self_guard(BPF_CORE_READ(root, d_inode), root,
                              SELF_NO_UMOUNT, SOP_UMOUNT, (__u8)flags));
}

/* ===========================================================================
 * Tier 1 — opt-in, one flag.
 * =========================================================================== */

SEC("lsm/locked_down")
long BPF_PROG(wax_self_lockdown, enum lockdown_reason what)
{
    struct self_config *cfg;

    /* CONFIG_SECURITY_LOCKDOWN_LSM=y on RHEL 9 and the running level is [none]
     * (verified: /sys/kernel/security/lockdown reads "[none] integrity
     * confidentiality", and /sys/kernel/security/lsm lists lockdown). That means
     * every security_locked_down() call site exists and currently returns 0, so
     * a program here gets to decide them — LOCKDOWN_KCORE, LOCKDOWN_DEV_MEM,
     * LOCKDOWN_KEXEC, LOCKDOWN_BPF_WRITE_USER and the rest — with no kernel
     * cmdline change and no reboot.
     *
     * A bitmask published from userspace rather than a switch: which reasons are
     * worth refusing is an operator decision, and the whole cost is one shift
     * and one test. The mask is zero by default, which makes this program inert
     * until someone asks for it. */
    cfg = self_cfg();
    if (!cfg || !cfg->lockdown_mask) return 0;
    if (cfg->mode == SMODE_DISARMED) return 0;
    if ((__u32)what >= 64) return 0;
    if (!(cfg->lockdown_mask & (1ULL << (__u32)what))) return 0;
    if (self_trusted()) return 0;
    return lsm_ret(self_deny(SOP_LOCKDOWN, SKIND_LOCKDOWN, 0, 0, (__u32)what, 0));
}

#endif /* DOOR_SELF_PROGS_H */
