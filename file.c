// SPDX-License-Identifier: GPL-2.0 OR MIT
// Dual-licensed; the kernel-facing license string stays GPL-compatible
// ("Dual MIT/GPL") so gpl_only helpers such as bpf_d_path remain usable.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 256
#define TTY_LEN  64
#define CMDLINE_LEN 512
/* Policy IDs are typically 32-character strings; 39 bytes + NUL also covers
 * dashed UUIDs, and 40 keeps the fields after it naturally aligned. */
#define POLICY_ID_LEN 40
#define MAX_RULES 512
#define OP_EXEC    1
#define OP_READ    2
#define OP_WRITE   3
/* Operations below are write-class: they are governed by the write rules. */
#define OP_UNLINK  4
#define OP_RENAME  5
#define OP_CHMOD   6
#define OP_CHOWN   7
#define OP_SETTIME 8
#define OP_MKDIR   9
#define OP_SYMLINK 10
#define OP_LINK    11
#define OP_MKNOD   12
#define OP_TRUNCATE 13
#define FMODE_READ  0x00000001
#define FMODE_WRITE 0x00000002
/* include/linux/fs.h iattr ia_valid flags */
#define ATTR_SIZE      (1 << 3)
#define ATTR_MTIME     (1 << 5)
#define ATTR_MTIME_SET (1 << 8)
#define MAX_DENTRY_DEPTH 48
#define MAX_CGROUP_DEPTH 32
#define MODE_ENFORCE 0
#define MODE_WARN    1
/* Permission bits selecting which operations a rule governs. */
#define PERM_EXEC  1
#define PERM_READ  2
#define PERM_WRITE 4

/* A rule matches when the current process image matches exec_path, the target
 * matches path, and the operation's permission bit is set. Patterns are stored
 * unescaped; the wild bitmaps mark which positions are '?'/'*' wildcards, so a
 * literal '*' or '?' byte (escaped in JSON) has its bit clear. An empty
 * pattern (leading NUL, bit 0 clear) always matches.
 *
 * A pattern whose first byte is a wildcard '*' is a suffix match. The loader
 * fills the matching *_suffix_len with the number of pattern bytes after that
 * '*', which is what lets the matcher jump straight to the path's tail instead
 * of backtracking. It is 0 for prefix and empty patterns. */
struct rule {
    char exec_path[PATH_LEN];
    char path[PATH_LEN];
    __u8 exec_wild[PATH_LEN / 8];
    __u8 path_wild[PATH_LEN / 8];
    __u8 enabled;
    __u8 permission;
    __u8 deny;
    __u8 no_event;
    __u8 exec_suffix_len;
    __u8 path_suffix_len;
    __u8 _pad[2];
};

struct policy_meta {
    __u32 rule_count;
    char id[POLICY_ID_LEN]; /* NUL-terminated policy id */
};

struct policy_slot {
    union {
        struct policy_meta meta;
        struct rule rule;
    };
};

struct runtime_config { __u32 mode; };

struct event {
    __u32 uid;       /* audit login uid */
    __u32 real_uid;  /* real uid at time of operation */
    __u64 create_timestamp_ns;
    __u64 cgroup_id; /* cgroup v2 id (kernfs inode) */
    __u32 audit_session_id;
    __u8 status;
    __u8 operation;
    __u16 _pad;
    char path[PATH_LEN];
    char executable_path[PATH_LEN];
    char cgroup[PATH_LEN]; /* cgroup v2 path, best-effort */
    char policy_id[POLICY_ID_LEN]; /* deciding policy; empty when the uid has no policy */
    char tty[TTY_LEN];
    __u32 pid;
    __u32 ppid;
    __u32 cmdline_len;
    char cmdline[CMDLINE_LEN];
};

struct executable_path_scratch {
    char path[PATH_LEN];
};

/* Twice PATH_LEN: appending a dentry name after a bpf_d_path result uses a
 * variable offset plus a fixed-size copy, and the verifier bounds that access
 * by the two worst cases added together. Rules never match past PATH_LEN. */
struct file_path_scratch {
    char path[PATH_LEN * 2];
};

/* Right-to-left dentry-walk buffer for hooks that only receive a dentry
 * (inode_setattr). Same 2x headroom rationale as file_path_scratch. */
struct dentry_walk_scratch {
    char build[PATH_LEN * 2];
    char name[PATH_LEN];
};

/* Every inner policy map has this fixed layout: meta then the ordered rules. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 + MAX_RULES);
    __type(key, __u32);
    __type(value, struct policy_slot);
} policy_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __array(values, typeof(policy_template));
} active_policy_by_uid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_config);
} runtime_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct executable_path_scratch);
} executable_path_scratch SEC(".maps");

/* bpf_d_path output is kept off the BPF call stack. check() invokes policy
 * callbacks and path matchers, so a 256-byte local buffer would exceed the
 * verifier's 512-byte combined call-stack limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_path_scratch);
} file_path_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dentry_walk_scratch);
} dentry_walk_scratch_map SEC(".maps");

/* The execute controls live in exec.c, which is included at the end of this
 * file — by then emit_event(), check() and lsm_ret(), which it builds on, are
 * all in scope. These are the two entry points the policy engine below calls
 * into it, declared here so the dependency between the files runs one way. */
static __always_inline void queue_exec_event(__u32 uid, __u8 status, const char *path,
                                             const char *policy_id);
static __always_inline void clear_pending_exec(void);

/*
 * Verifier-friendly glob matcher. Pattern bytes are stored unescaped; the wild
 * bitmap marks which positions are wildcards: '?' matches one non-NUL byte and
 * '*' is supported as a terminal wildcard (for example, "/usr/bin/" plus '*').
 * A '*' or '?' byte without its wild bit set matches only the literal byte.
 * Keeping the character scan in bpf_loop's callback prevents it from
 * multiplying the states of the outer policy loop on older 5.14-based
 * verifiers.
 */
struct path_match_ctx {
    const char *rule;
    const __u8 *wild;
    const char *path;
    __u32 start; /* suffix match: path offset the comparison starts at */
    __u8 matched;
};

static long match_path_cb(__u32 i, void *data)
{
    struct path_match_ctx *ctx = data;
    char rc, pc;
    __u8 w;

    if (i >= PATH_LEN) return 1;
    barrier_var(i);
    rc = ctx->rule[i];
    pc = ctx->path[i];
    w = ctx->wild[i >> 3] & (1 << (i & 7));

    if (w && rc == '*') {
        ctx->matched = 1;
        return 1;
    }
    if (rc == '\0') {
        ctx->matched = pc == '\0';
        return 1;
    }
    if (w && rc == '?') return pc == '\0';
    return rc != pc;
}

/* Suffix matcher for patterns that lead with a wildcard '*'. The wildcard's
 * span is fixed rather than searched — the loader supplies the suffix length,
 * so the comparison simply starts at path_len - suffix_len and walks forward,
 * keeping this the same single scan as the prefix case. Pattern index i + 1
 * skips the leading '*'; ctx->start is bounded by the caller so every path
 * index stays inside PATH_LEN. */
static long match_suffix_cb(__u32 i, void *data)
{
    struct path_match_ctx *ctx = data;
    __u32 ri = i + 1, pi = ctx->start + i;
    char rc, pc;
    __u8 w;

    if (ri >= PATH_LEN) return 1;
    barrier_var(ri);
    rc = ctx->rule[ri];
    if (rc == '\0') {           /* the whole suffix compared equal */
        ctx->matched = 1;
        return 1;
    }
    if (pi >= PATH_LEN) return 1;
    barrier_var(pi);
    pc = ctx->path[pi];
    w = ctx->wild[ri >> 3] & (1 << (ri & 7));

    if (w && rc == '?') return pc == '\0';
    return rc != pc;
}

/* A leading NUL with its wild bit clear is the "always matches any path"
 * pattern. Patterns must be NUL-terminated within PATH_LEN by the loader; a
 * pattern that fills all PATH_LEN bytes without a NUL never sets matched below,
 * so it safely fails to match rather than reading past the buffer. */
static __always_inline int pattern_is_empty(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '\0' && !(wild[0] & 1);
}

/* A wildcard '*' in position 0 anchors the pattern to the path's tail. An
 * escaped literal '*' has its wild bit clear and is not a suffix pattern. */
static __always_inline int pattern_is_suffix(const char *pattern, const __u8 *wild)
{
    return pattern[0] == '*' && (wild[0] & 1);
}

static __always_inline int match_path_pattern(const char *pattern, const __u8 *wild,
                                              __u8 suffix_len, const char *path,
                                              __u32 path_len)
{
    struct path_match_ctx ctx = {
        .rule = pattern,
        .wild = wild,
        .path = path,
    };

    if (pattern_is_empty(pattern, wild)) return 1;
    if (pattern_is_suffix(pattern, wild)) {
        /* A bare "*" carries no suffix and matches like the empty pattern. */
        if (suffix_len == 0) return 1;
        /* Paths that did not fit PATH_LEN were truncated, so their real tail
         * is not observable here and a suffix rule must not claim a match. */
        if (path_len >= PATH_LEN) return 0;
        if (suffix_len > path_len) return 0;
        ctx.start = path_len - suffix_len;
        bpf_loop(PATH_LEN, match_suffix_cb, &ctx, 0);
        return ctx.matched;
    }
    bpf_loop(PATH_LEN, match_path_cb, &ctx, 0);
    return ctx.matched;
}

/* Rebuild the cgroup v2 path right-to-left over the kernfs parent chain,
 * mirroring the dentry walk below. Reuses dentry_walk_scratch: by the time an
 * event is emitted every hook has already copied its walked path into
 * file_path_scratch, so the buffer is idle. */
struct cgroup_walk_ctx {
    struct kernfs_node *kn;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

/*
 * RHEL 9.8 (kernel 5.14.0-687) backported the upstream rename of
 * kernfs_node::parent to kernfs_node::__parent (the RCU conversion). The
 * build-time vmlinux.h only carries one of the two names, so read whichever the
 * running kernel actually exposes. bpf_core_field_exists() folds the unused
 * branch to a constant the verifier prunes, so the CO-RE relocation for the
 * field that is absent on the target never sits on a live code path.
 */
struct kernfs_node___parent_flavor {
    struct kernfs_node___parent_flavor *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kernfs_node_parent(struct kernfs_node *kn)
{
    struct kernfs_node___parent_flavor *k = (void *)kn;

    if (bpf_core_field_exists(k->__parent))
        return (struct kernfs_node *)BPF_CORE_READ(k, __parent);
    return BPF_CORE_READ(kn, parent);
}

static long cgroup_walk_cb(__u32 i, void *data)
{
    struct cgroup_walk_ctx *ctx = data;
    struct kernfs_node *kn = ctx->kn, *parent;
    const char *name;
    __u32 pos, sz;
    long len;

    if (!kn) {
        ctx->failed = 1;
        return 1;
    }
    parent = kernfs_node_parent(kn);
    if (!parent) {                              /* kernfs root */
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(kn, name);
    len = bpf_probe_read_kernel_str(ctx->s->name, PATH_LEN, name);
    if (len <= 1) {
        ctx->failed = 1;
        return 1;
    }
    sz = (__u32)len - 1;                        /* component bytes, no NUL */
    if (sz >= PATH_LEN || ctx->pos < sz + 1) {  /* out of path budget */
        ctx->failed = 1;
        return 1;
    }
    pos = ctx->pos - (sz + 1);
    if (pos >= PATH_LEN) {                      /* bound for the verifier */
        ctx->failed = 1;
        return 1;
    }
    ctx->s->build[pos] = '/';
    if (bpf_probe_read_kernel(&ctx->s->build[pos + 1], sz, ctx->s->name) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->pos = pos;
    ctx->kn = parent;
    return 0;
}

static __always_inline void fill_cgroup(struct event *e, struct task_struct *task)
{
    __u32 zero = 0;
    struct kernfs_node *kn;
    struct dentry_walk_scratch *s;
    struct cgroup_walk_ctx ctx;

    e->cgroup_id = bpf_get_current_cgroup_id();
    kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn) return;
    s = bpf_map_lookup_elem(&dentry_walk_scratch_map, &zero);
    if (!s) return;
    s->build[PATH_LEN] = '\0';
    ctx = (struct cgroup_walk_ctx){ .kn = kn, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_CGROUP_DEPTH, cgroup_walk_cb, &ctx, 0);
    /* Leave the field empty rather than truncated on an incomplete walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return;
    if (ctx.pos == PATH_LEN) {                  /* task is in the root cgroup */
        e->cgroup[0] = '/';
        e->cgroup[1] = '\0';
        return;
    }
    bpf_probe_read_kernel_str(e->cgroup, PATH_LEN, &s->build[ctx.pos]);
}

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

static __always_inline void emit_event(__u32 uid, __u8 op, __u8 status,
                                       const char *path, const char *executable_path,
                                       const char *policy_id, __u8 capture_cmdline)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
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

struct policy_check_ctx {
    void *inner;
    const char *path;
    const char *executable_path;
    const char *policy_id;
    __u32 uid;
    __u32 count;
    /* strlen of the two paths, for suffix matching. A value >= PATH_LEN means
     * the path did not fit the buffer and was truncated. */
    __u32 path_len;
    __u32 exec_path_len;
    __u8 op;
    __u8 perm_bit;
    __u8 matched;
    __u8 exec_resolved; /* current process image was resolved via bpf_d_path */
    int result;
};

/*
 * Keep rule traversal inside bpf_loop rather than a C-bounded loop.  Larger
 * policy limits would otherwise be unrolled by clang and exceed the verifier's
 * instruction limit before the program can load.
 */
static long check_rule_cb(__u32 i, void *data)
{
    struct policy_check_ctx *ctx = data;
    __u32 zero = 0, index;
    struct policy_slot *slot;
    struct rule *r;
    struct runtime_config *cfg;
    __u8 denied, status;

    if (i >= ctx->count) return 1;
    index = 1 + i;
    slot = bpf_map_lookup_elem(ctx->inner, &index);
    if (!slot || !slot->rule.enabled) return 0;
    r = &slot->rule;
    if (!(r->permission & ctx->perm_bit)) return 0;
    if (ctx->executable_path) {
        if (ctx->exec_resolved) {
            if (!match_path_pattern(r->exec_path, r->exec_wild,
                                    r->exec_suffix_len, ctx->executable_path,
                                    ctx->exec_path_len))
                return 0;
        } else if (!pattern_is_empty(r->exec_path, r->exec_wild)) {
            /* The process image could not be resolved and this rule is scoped
             * to a specific exec_path, so we cannot confirm the match. Fail
             * closed for deny rules (treat the exec_path as matching so the
             * deny still fires); skip permissive rules so an unverified allow
             * cannot shadow a later deny. The path test below still applies. */
            if (!r->deny) return 0;
        }
    }
    if (!match_path_pattern(r->path, r->path_wild, r->path_suffix_len, ctx->path,
                            ctx->path_len))
        return 0;

    ctx->matched = 1;
    cfg = bpf_map_lookup_elem(&runtime_config_map, &zero);
    denied = r->deny && (!cfg || cfg->mode == MODE_ENFORCE);
    status = r->deny && cfg && cfg->mode == MODE_WARN ? 'W' : r->deny ? 'F' : 'S';
    if (!r->no_event) {
        if (ctx->op == OP_EXEC && !denied)
            queue_exec_event(ctx->uid, status, ctx->path, ctx->policy_id);
        else
            emit_event(ctx->uid, ctx->op, status, ctx->path, ctx->executable_path,
                       ctx->policy_id, ctx->op != OP_EXEC);
    }
    ctx->result = denied ? -13 /* EACCES */ : 0;
    return 1;
}

static __always_inline int task_is_exempt(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, sessionid) == (__u32)-1;
}

/* Evaluate an already-resolved path against the caller's policy. Policies
 * are selected — and events attributed — by the audit login uid, which
 * pam_loginuid assigns at login and survives su/sudo, so a user stays under
 * their own policy after switching to root. The operation selects the
 * permission bit rules must carry: exec(1), read(2), or write(4) for every
 * write-class operation (write, truncate, unlink, rename, chmod, chown,
 * settime, mkdir, symlink, link, mknod). The first rule whose permission bit,
 * exec_path pattern (current process image) and path pattern all match
 * decides the outcome. */
static __always_inline int check_policy(const char *path, __u32 path_len, __u8 op)
{
    __u32 uid, zero = 0, count, exec_path_len = 0;
    struct task_struct *task;
    struct policy_slot *meta;
    struct policy_check_ctx ctx;
    struct executable_path_scratch *executable_scratch;
    struct mm_struct *mm;
    struct file *exe_file;
    void *inner;
    const char *executable_path = 0;
    __u8 exec_resolved = 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    uid = BPF_CORE_READ(task, loginuid.val);
    inner = bpf_map_lookup_elem(&active_policy_by_uid, &uid);
    if (!inner) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0);
        return 0;
    }
    meta = bpf_map_lookup_elem(inner, &zero);
    if (!meta) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, 0);
        return 0;
    }
    count = meta->meta.rule_count;
    if (count > MAX_RULES) count = MAX_RULES;
    if (count == 0) {
        if (op == OP_EXEC) queue_exec_event(uid, 'S', path, meta->meta.id);
        return 0;
    }
    /* Resolve the current process image for exec_path matching. For OP_EXEC
     * this is still the invoking image (e.g. the shell): bprm_check runs
     * before the new image is committed. */
    executable_scratch = bpf_map_lookup_elem(&executable_path_scratch, &zero);
    if (executable_scratch) {
        executable_scratch->path[0] = '\0';
        executable_path = executable_scratch->path;
        /* Keep these as typed pointer dereferences. bpf_d_path requires a
         * trusted PTR_TO_BTF_ID; BPF_CORE_READ would turn exe_file into a
         * scalar from the verifier's perspective. */
        mm = task->mm;
        exe_file = mm ? mm->exe_file : 0;
        if (exe_file) {
            long n = bpf_d_path(&exe_file->f_path, executable_scratch->path,
                                sizeof(executable_scratch->path));

            if (n > 0) {
                exec_resolved = 1;
                exec_path_len = (__u32)n - 1;   /* n counts the NUL */
            }
        }
    }

    ctx = (struct policy_check_ctx){
        .inner = inner,
        .path = path,
        .executable_path = executable_path,
        .policy_id = meta->meta.id,
        .uid = uid,
        .count = count,
        .path_len = path_len,
        .exec_path_len = exec_path_len,
        .op = op,
        .perm_bit = op == OP_EXEC ? PERM_EXEC :
                    op == OP_READ ? PERM_READ : PERM_WRITE,
        .exec_resolved = exec_resolved,
    };
    bpf_loop(MAX_RULES, check_rule_cb, &ctx, 0);
    /* A configured policy still audits allowed executables that did not match
     * any rule.  Allowed matching rules have already queued their own event
     * in check_rule_cb. */
    if (op == OP_EXEC && !ctx.matched)
        queue_exec_event(uid, 'S', path, meta->meta.id);
    return ctx.result;
}

static __always_inline int check(struct file *file, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *path_scratch;
    long len;

    if (task_is_exempt()) {
        /* Do not retain an older pending exec event for an exempt task. */
        if (op == OP_EXEC) clear_pending_exec();
        return 0;
    }
    path_scratch = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!path_scratch) return 0;
    path_scratch->path[0] = '\0';
    len = bpf_d_path(&file->f_path, path_scratch->path, PATH_LEN);
    if (len <= 0) return 0;
    if (op == OP_EXEC) clear_pending_exec();
    return check_policy(path_scratch->path, (__u32)len - 1, op);
}

/* Resolve "parent directory path" + "/" + "dentry name" into the shared path
 * scratch and run the write-class policy on it. Used by
 * unlink/rmdir/mkdir/symlink/link/mknod/rename,
 * whose hooks receive the target as a (parent path, dentry) pair. */
static __always_inline int check_dir_dentry(const struct path *dir,
                                            struct dentry *dentry, __u8 op)
{
    __u32 zero = 0, off;
    struct file_path_scratch *ps;
    const unsigned char *name;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)dir, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    off = (__u32)len - 1;                       /* index of the NUL */
    if (off >= PATH_LEN) return 0;
    /* barrier_var keeps clang from re-deriving these offsets from len, which
     * would drop the masks the verifier needs to see. */
    barrier_var(off);
    off &= PATH_LEN - 1;
    if (off > 0) {
        __u32 prev = off - 1;

        barrier_var(prev);
        prev &= PATH_LEN - 1;
        if (ps->path[prev] == '/') off = prev;  /* parent is "/" */
    }
    ps->path[off] = '/';
    name = BPF_CORE_READ(dentry, d_name.name);
    len = bpf_probe_read_kernel_str(&ps->path[off + 1], PATH_LEN, name);
    if (len <= 0) return 0;
    /* off + 1 leading bytes plus len - 1 component bytes. This is the one
     * producer that can exceed PATH_LEN, which only suffix rules care about;
     * they decline to match a path they cannot see the end of. */
    return check_policy(ps->path, off + (__u32)len, op);
}

/* Hooks that receive the target as a struct path resolve it directly. */
static __always_inline int check_path_op(const struct path *p, __u8 op)
{
    __u32 zero = 0;
    struct file_path_scratch *ps;
    long len;

    if (task_is_exempt()) return 0;
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!ps) return 0;
    ps->path[0] = '\0';
    len = bpf_d_path((struct path *)p, ps->path, PATH_LEN);
    if (len <= 0) return 0;
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * inode_setattr only receives a dentry, so the path is rebuilt by walking
 * d_parent toward the filesystem root, writing components right-to-left.
 * The result lacks the mount prefix for files on non-root mounts; rules are
 * matched against the path as seen from that filesystem's root.
 */
struct dentry_walk_ctx {
    struct dentry *d;
    struct dentry_walk_scratch *s;
    __u32 pos;
    __u8 done;
    __u8 failed;
};

static long dentry_walk_cb(__u32 i, void *data)
{
    struct dentry_walk_ctx *ctx = data;
    struct dentry *d = ctx->d, *parent;
    const unsigned char *name;
    __u32 pos, sz;
    long len;

    if (!d) {
        ctx->failed = 1;
        return 1;
    }
    parent = BPF_CORE_READ(d, d_parent);
    if (parent == d) {
        ctx->done = 1;
        return 1;
    }
    name = BPF_CORE_READ(d, d_name.name);
    len = bpf_probe_read_kernel_str(ctx->s->name, PATH_LEN, name);
    if (len <= 1) {
        ctx->failed = 1;
        return 1;
    }
    sz = (__u32)len - 1;                        /* component bytes, no NUL */
    if (sz >= PATH_LEN || ctx->pos < sz + 1) {  /* out of path budget */
        ctx->failed = 1;
        return 1;
    }
    pos = ctx->pos - (sz + 1);
    if (pos >= PATH_LEN) {                      /* bound for the verifier */
        ctx->failed = 1;
        return 1;
    }
    ctx->s->build[pos] = '/';
    if (bpf_probe_read_kernel(&ctx->s->build[pos + 1], sz, ctx->s->name) < 0) {
        ctx->failed = 1;
        return 1;
    }
    ctx->pos = pos;
    ctx->d = parent;
    return 0;
}

static __always_inline int check_dentry_op(struct dentry *dentry, __u8 op)
{
    __u32 zero = 0;
    struct dentry_walk_scratch *s;
    struct file_path_scratch *ps;
    struct dentry_walk_ctx ctx;
    long len;

    if (task_is_exempt()) return 0;
    s = bpf_map_lookup_elem(&dentry_walk_scratch_map, &zero);
    ps = bpf_map_lookup_elem(&file_path_scratch, &zero);
    if (!s || !ps) return 0;
    s->build[PATH_LEN] = '\0';
    ctx = (struct dentry_walk_ctx){ .d = dentry, .s = s, .pos = PATH_LEN };
    bpf_loop(MAX_DENTRY_DEPTH, dentry_walk_cb, &ctx, 0);
    /* Allow rather than mis-match on an incomplete (too deep/long) walk. */
    if (!ctx.done || ctx.failed || ctx.pos > PATH_LEN) return 0;
    if (ctx.pos == PATH_LEN) {                  /* dentry was the root itself */
        ps->path[0] = '/';
        ps->path[1] = '\0';
        len = 2;
    } else if ((len = bpf_probe_read_kernel_str(ps->path, PATH_LEN,
                                                &s->build[ctx.pos])) <= 0) {
        return 0;
    }
    return check_policy(ps->path, (__u32)len - 1, op);
}

/*
 * Strict LSM verifiers (e.g. RHEL 9.8, kernel 5.14.0-687) require every hook to
 * return a value provably within [-4095, 0]. Two things are needed. First, the
 * hooks return `long` so clang sign-extends the result into the full 64-bit R0:
 * an `int` return emits a 32-bit move that zero-extends, turning a negative
 * errno (e.g. -EACCES) into a large positive value the verifier rejects.
 * Second, lsm_ret() clamps the value with signed comparisons so the verifier
 * can bound smin/smax to exactly [-4095, 0]. Valid results (0, -EACCES, or a
 * prior hook's errno) pass through unchanged. Older 5.14 verifiers (RHEL 9.5)
 * accepted the un-clamped `int` form, so this only tightens portability.
 */
static __always_inline long lsm_ret(long r)
{
    /* barrier_var keeps clang from proving the value's range at compile time
     * (e.g. that check() only yields 0 or -EACCES) and then dropping a clamp or
     * lowering it to a 32-bit subregister compare the verifier cannot tie back
     * to the returned register. Forcing an opaque 64-bit value before each
     * signed compare makes the verifier track smin/smax on the exact register
     * that is returned. */
    barrier_var(r);
    if (r < -4095)
        r = -4095;
    barrier_var(r);
    if (r > 0)
        r = 0;
    barrier_var(r);
    return r;
}

SEC("lsm/file_open")
long BPF_PROG(check_file_open, struct file *file, int ret)
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
long BPF_PROG(check_path_unlink, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_rmdir")
long BPF_PROG(check_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_UNLINK));
}

SEC("lsm/path_mkdir")
long BPF_PROG(check_path_mkdir, const struct path *dir, struct dentry *dentry,
             umode_t mode)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_MKDIR));
}

SEC("lsm/path_symlink")
long BPF_PROG(check_path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    return lsm_ret(check_dir_dentry(dir, dentry, OP_SYMLINK));
}

SEC("lsm/path_link")
long BPF_PROG(check_path_link, struct dentry *old_dentry, const struct path *new_dir,
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
long BPF_PROG(check_inode_mknod, struct inode *dir, struct dentry *dentry,
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
long BPF_PROG(check_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    /* Both sides are writes: moving a file out of a protected directory and
     * moving one in are each subject to the write rules. */
    int ret = check_dir_dentry(old_dir, old_dentry, OP_RENAME);

    if (ret) return lsm_ret(ret);
    return lsm_ret(check_dir_dentry(new_dir, new_dentry, OP_RENAME));
}

SEC("lsm/path_chmod")
long BPF_PROG(check_path_chmod, const struct path *path, umode_t mode)
{
    return lsm_ret(check_path_op(path, OP_CHMOD));
}

SEC("lsm/path_chown")
long BPF_PROG(check_path_chown, const struct path *path)
{
    return lsm_ret(check_path_op(path, OP_CHOWN));
}

SEC("lsm/path_truncate")
long BPF_PROG(check_path_truncate, const struct path *path)
{
    /* Path-based truncate()/truncate64() never opens the file, so
     * file_open(FMODE_WRITE) does not see it. Governing it here closes a
     * write-class bypass that would otherwise let a protected file be zeroed
     * without matching any rule. (ftruncate(fd) is already covered by
     * file_open, and O_TRUNC opens carry FMODE_WRITE there too.) */
    return lsm_ret(check_path_op(path, OP_TRUNCATE));
}

SEC("lsm/inode_setattr")
long BPF_PROG(check_inode_setattr, struct dentry *dentry, struct iattr *attr)
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

/* The execute controls. Included last: everything it builds on — emit_event(),
 * check() and lsm_ret() — is defined above, and it in turn supplies the
 * queue_exec_event()/clear_pending_exec() declared near the top of this file. */
#include "exec.c"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
