// SPDX-License-Identifier: GPL-2.0 OR MIT
//
// pam_wood.so — records who logged in on each audit session, so the LSM
// policy can control a shared account per person.
//
// The login uid alone cannot tell two people apart on an account like `oracle`
// or `wasadm`. PAM is the only place that knows which of them is arriving, so
// this module writes that name into the BPF map wdog pins, keyed by the audit
// session id. door/file.c and door/net.c then resolve it on every check —
// session id to name here, name to the id their rules carry via a second table
// wdog maintains — and match that against each rule's employee_id.
//
// This module only ever writes the name. It knows nothing about ids, which
// belong to whatever policy happens to be installed and change on nobody's
// schedule but wdog's.
//
// Deliberately no libbpf. All this needs is three bpf(2) commands, and the
// module is loaded into sshd's address space on every login — a dependency on
// libbpf (and through it zlib and elfutils) is a liability there, and it would
// make libbpf a runtime requirement on every deployed host. See pam/Makefile.
//
// Placement in the stack matters:
//
//     session    required   pam_loginuid.so
//     session    optional   pam_wood.so
//
// pam_loginuid.so is what assigns the audit session id, so this module must run
// after it; before it, /proc/self/sessionid still reads -1 and there is nothing
// to key on. It is `optional` because nothing here is worth failing a login
// over — every path below returns PAM_SUCCESS and reports trouble to syslog.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Must equal EMPLOYEE_NAME_LEN in door/file.c and door/net.c: this struct is
 * the value layout of a map those two objects declare, and the kernel would
 * reject an update of the wrong size. */
#define EMPLOYEE_NAME_LEN 64

#define DEFAULT_MAP_PATH "/sys/fs/bpf/libwdoor/session_identity"
#define DEFAULT_ENV_NAME "PAM_EMPLOYEE_NAME"

/* Mirrors struct session_identity in door/file.c. login_uid is not a matching
 * criterion; it lets the kernel discard a record left behind by a session whose
 * id has since been reused. */
struct session_identity {
	char employee_name[EMPLOYEE_NAME_LEN];
	uint32_t login_uid;
	uint32_t _pad;
};

struct options {
	const char *map_path;
	const char *env_name;
	int debug;
	/* fallback_user makes an absent environment variable fall back to the
	 * login account name. Off by default: recording the account as the person
	 * would make the audit trail assert something PAM was never told. */
	int fallback_user;
};

static void parse_options(struct options *o, int argc, const char **argv)
{
	o->map_path = DEFAULT_MAP_PATH;
	o->env_name = DEFAULT_ENV_NAME;
	o->debug = 0;
	o->fallback_user = 0;
	for (int i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "map=", 4))
			o->map_path = argv[i] + 4;
		else if (!strncmp(argv[i], "env=", 4))
			o->env_name = argv[i] + 4;
		else if (!strcmp(argv[i], "debug"))
			o->debug = 1;
		else if (!strcmp(argv[i], "fallback=user"))
			o->fallback_user = 1;
	}
}

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* Open the pinned map. A failure here is the normal state when wdog has never
 * run on this host, so callers report it and carry on. */
static int map_open(const char *path)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = (uint64_t)(unsigned long)path;
	return bpf(BPF_OBJ_GET, &attr);
}

/* Read one unsigned value out of a procfs file. Returns -1 on any failure, and
 * on the two files this is used for that is indistinguishable from the "(u32)-1
 * means unset" the kernel itself writes — which is what the callers want. */
static long read_proc_u32(const char *path)
{
	char buf[32];
	ssize_t n;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	errno = 0;
	unsigned long v = strtoul(buf, NULL, 10);
	if (errno != 0 || v > 0xffffffffUL || v == 0xffffffffUL)
		return -1;
	return (long)v;
}

/* The audit session this login was given, or -1 when it has none — which on a
 * correctly ordered stack means pam_loginuid.so has not run yet. */
static long current_session_id(void)
{
	return read_proc_u32("/proc/self/sessionid");
}

static long current_login_uid(void)
{
	return read_proc_u32("/proc/self/loginuid");
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options o;
	struct session_identity id;
	union bpf_attr attr;
	const char *name;
	long sid, uid;
	uint32_t key;
	int fd;

	(void)flags;
	parse_options(&o, argc, argv);

	/* test only */	
	pam_putenv(pamh, "PAM_EMPLOYEE_NAME=mark1");

	name = pam_getenv(pamh, o.env_name);
	pam_syslog(pamh, LOG_WARNING, "===1 %s", name);
	if ((!name || !*name) && o.fallback_user) {
		const char *user = NULL;

		if (pam_get_item(pamh, PAM_USER, (const void **)&user) == PAM_SUCCESS)
			name = user;
	}
	if (!name || !*name) {
		/* Nothing to record. Rules naming an employee then match nothing for
		 * this session, which is the documented behaviour rather than a
		 * failure — but say so once, since a whole stack misconfigured this
		 * way would otherwise look like the policy silently not working. */
		if (o.debug)
			pam_syslog(pamh, LOG_DEBUG, "%s is unset; session recorded with no employee name",
				   o.env_name);
		return PAM_SUCCESS;
	}

	sid = current_session_id();
	if (sid < 0) {
		pam_syslog(pamh, LOG_WARNING,
			   "no audit session id; place pam_wood.so AFTER pam_loginuid.so in the session stack");
		return PAM_SUCCESS;
	}
	uid = current_login_uid();
	if (uid < 0) {
		pam_syslog(pamh, LOG_WARNING, "no audit login uid for session %ld", sid);
		return PAM_SUCCESS;
	}

	fd = map_open(o.map_path);
	if (fd < 0) {
		pam_syslog(pamh, LOG_WARNING, "opening %s: %m (is wdog running?)", o.map_path);
		return PAM_SUCCESS;
	}

	/* memset first, and note that this is required rather than tidy: the kernel
	 * uses this name as a fixed-width hash key to look up the employee id its
	 * rules carry, and a hash key is compared as a block of bytes. Anything left
	 * after the terminator would hash to something no rule knows, and the login
	 * would silently go unidentified. strncpy pads to its bound for the same
	 * reason. */
	memset(&id, 0, sizeof(id));
	/* One byte short of the field, so the name is always NUL-terminated. A
	 * longer name is truncated here and simply will not equal any rule — the
	 * loader rejects rules above the same bound, so the two agree. */
	strncpy(id.employee_name, name, EMPLOYEE_NAME_LEN - 1);
	id.login_uid = (uint32_t)uid;
	key = (uint32_t)sid;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(unsigned long)&key;
	attr.value = (uint64_t)(unsigned long)&id;
	attr.flags = BPF_ANY;
	pam_syslog(pamh, LOG_WARNING, "===2 %s", name);
	if (bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0) {
		/* E2BIG is the map being full: sessions have accumulated faster than
		 * they were reaped. Worth naming, because from here on no new login
		 * can be identified at all. */
		pam_syslog(pamh, LOG_WARNING, "===3 %s", name);
		if (errno == E2BIG)
			pam_syslog(pamh, LOG_ERR,
				   "%s is full; new logins cannot be identified until entries are freed",
				   o.map_path);
		else
			pam_syslog(pamh, LOG_INFO, "recording session %ld: %m", sid);
	} else if (o.debug) {
		pam_syslog(pamh, LOG_WARNING, "===4 %s", name);
		pam_syslog(pamh, LOG_INFO, "session %ld (uid %ld) recorded as %s",
			   sid, uid, id.employee_name);
	}
	pam_syslog(pamh, LOG_WARNING, "===5 %s", name);
	close(fd);
	return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options o;
	union bpf_attr attr;
	long sid;
	uint32_t key;
	int fd;

	(void)flags;
	parse_options(&o, argc, argv);

	sid = current_session_id();
	if (sid < 0)
		return PAM_SUCCESS;
	fd = map_open(o.map_path);
	if (fd < 0)
		return PAM_SUCCESS; /* nothing pinned; nothing to clean up */
	key = (uint32_t)sid;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(unsigned long)&key;
	/* ENOENT means there was no record — an open_session that found no name,
	 * or wdog's reaper got there first. Neither is worth a log line. */
	if (bpf(BPF_MAP_DELETE_ELEM, &attr) < 0 && errno != ENOENT)
		pam_syslog(pamh, LOG_WARNING, "clearing session %ld: %m", sid);
	else if (o.debug)
		pam_syslog(pamh, LOG_DEBUG, "session %ld cleared", sid);
	close(fd);
	return PAM_SUCCESS;
}
