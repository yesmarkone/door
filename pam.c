// SPDX-License-Identifier: GPL-2.0 OR MIT
//
// pam_wood.so — records who logged in on each audit session, so the LSM
// policy can control a shared account per person.
//
// The login uid alone cannot tell two people apart on an account like `oracle`
// or `wasadm`. PAM is the only place that knows which of them is arriving, so
// this module writes that name into the BPF map wdog pins, keyed by the audit
// session id. door/file.c and door/net.c resolve it on every check — session id
// to name here, name to the id their rules carry via a second table wdog
// maintains — and match that against each rule's employee_id. This module only
// ever writes the name; the ids belong to whatever policy is installed.
//
// It records the session's ORIGIN for the same reason: nothing downstream can
// tell a child of sshd from a child of crond. /etc/pam.d/crond runs
// pam_loginuid too, so a cron job carries a real audit session id and the
// target user's login uid exactly as an ssh login does, and the kernel sees two
// tasks that agree on every field it has. The difference survives only in PAM
// (PAM_SERVICE, PAM_RHOST), and this module is the code loaded into sshd on one
// login and crond on the next — so it classifies once, here.
//
// Origin is therefore a property of the SESSION, not of the process: every
// descendant inherits it through task->sessionid, with no process tree to walk.
// Ancestry rots (setsid, nohup, a shell under tmux); an audit session id does
// not. It rides through su and sudo untouched for the same reason the login uid
// does — neither runs pam_loginuid, so neither opens a new session.
//
// The stacks that most need the origin are the ones with nobody to name, so
// recording it must not require an identity. See `origin_only`:
//
//     # /etc/pam.d/crond, /etc/pam.d/atd
//     session    required   pam_loginuid.so
//     session    optional   pam_wood.so origin=scheduled origin_only
//
// Deliberately no libbpf: this needs three bpf(2) commands, and the module is
// loaded into sshd's address space on every login. Depending on libbpf (and
// through it zlib and elfutils) there is a liability, and it would make libbpf a
// runtime requirement on every deployed host. See pam/Makefile.
//
// Placement and control flag:
//
//     session    required   pam_loginuid.so
//     session    required   pam_wood.so
//
// pam_loginuid.so assigns the audit session id, so this module must run after
// it; before it, /proc/self/sessionid still reads -1 and there is nothing to key
// on.
//
// `required`, because a login this module cannot identify is refused:
// open_session returns PAM_SESSION_ERR when the variable naming the person is
// unset or empty. That is the ONLY path here that fails a login. Everything else
// — no audit session id yet, no pin to write to, a full map — returns
// PAM_SUCCESS and reports to syslog, because an unidentified session is either
// already contained by the policy's catch-all deny rule or wdog is down and
// there is no policy at all, and refusing logins then buys nothing. An unset
// variable is different in kind: the front-end module that was supposed to say
// who is arriving never did.
//
// `optional` restores the previous never-fail behaviour verbatim. An account
// that must survive a broken identification path (root, for recovery) belongs in
// the stack rather than in an option here:
//
//     session    [success=1 default=ignore]   pam_succeed_if.so user = root quiet
//     session    required                     pam_wood.so

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
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
/* Must equal SESSION_SERVICE_LEN and SESSION_RHOST_LEN in door/file_const.h,
 * for the same reason. */
#define SESSION_SERVICE_LEN 32
#define SESSION_RHOST_LEN   64

/* Must equal the ORIGIN_* codes in door/file_const.h. This module is the ONLY
 * writer of this field: nothing else on the host is in a position to know. See
 * classify_origin() below for how each is decided. */
#define ORIGIN_UNKNOWN   0u
#define ORIGIN_REMOTE    1u
#define ORIGIN_CONSOLE   2u
#define ORIGIN_SCHEDULED 3u
#define ORIGIN_SERVICE   4u

/* The origin field's high bits are flags. SESSION_CLOSED is what close_session
 * sets INSTEAD of deleting the record, so that a login whose processes outlive
 * it — a remote-IDE server, nohup, tmux, setsid — keeps its employee name and
 * its origin for as long as those processes run. door/file_const.h carries the
 * reasoning; this module is the only writer of the bit, as it is of the field. */
#define SESSION_CLOSED   (1u << 31)

#define DEFAULT_MAP_PATH "/sys/fs/bpf/wax/wax_session_identity"
#define DEFAULT_ENV_NAME "PAM_EMPLOYEE_NAME"

/* Mirrors struct session_identity in door/file.c. login_uid is not a matching
 * criterion; it lets the kernel discard a record left behind by a session whose
 * id has since been reused. login_time_ns is written here and read only by
 * wdog, to stamp its audit lines with when the session logged in; zero means
 * "not recorded" and wdog approximates it from /proc instead.
 *
 * origin says where the session came from — remote, console, scheduled, service
 * — and is the one field added with it that the kernel matches on. service and
 * rhost are the raw PAM items it was decided from, recorded for the audit line
 * and read by nothing.
 *
 * This module is where the origin axis is decided because this module is the
 * only code in the system that is in a position to decide it. It is loaded into
 * sshd's address space on one login and crond's on the next, and PAM hands it
 * the service name and the remote host of whichever it is. A child of sshd and
 * a child of crond are otherwise indistinguishable — same login uid, same audit
 * session id, both with a PAM session — so everything downstream depends on
 * this being recorded here and recorded correctly.
 *
 * The size is an interface, and an unusually unforgiving one: BPF_MAP_UPDATE_ELEM
 * carries no value size, so the kernel copies map->value_size bytes from the
 * address below whatever this module believes that struct is. A module built
 * against an older layout therefore hands a newer map the difference in bytes
 * of this function's stack, with no error anywhere — and since this struct grew
 * 80 -> 176 for the origin axis, that difference is now 96 bytes of stack
 * readable by anyone who can dump the map. Hence the assert, and hence the rule
 * that this module ships with the daemons rather than on its own schedule:
 * `make && make pam-install` and a daemon restart are one operation. */
struct session_identity {
	char employee_name[EMPLOYEE_NAME_LEN];	/*   0 */
	uint32_t login_uid;			/*  64 */
	uint32_t origin;			/*  68 — ORIGIN_* */
	uint64_t login_time_ns;			/*  72 */
	char service[SESSION_SERVICE_LEN];	/*  80 — PAM_SERVICE */
	char rhost[SESSION_RHOST_LEN];		/* 112 — PAM_RHOST, empty if local */
};

_Static_assert(sizeof(struct session_identity) == 176,
	       "must match struct session_identity in door/file_types.h");
_Static_assert(__builtin_offsetof(struct session_identity, origin) == 68,
	       "must match struct session_identity in door/file_types.h");
_Static_assert(__builtin_offsetof(struct session_identity, login_time_ns) == 72,
	       "must match struct session_identity in door/file_types.h");

struct options {
	const char *map_path;
	const char *env_name;
	int debug;
	/* fallback_user makes an absent environment variable fall back to the
	 * login account name. Off by default: recording the account as the person
	 * would make the audit trail assert something PAM was never told. Note
	 * that it also keeps the module from ever refusing a session — a login
	 * always has an account name, so the name is never missing. */
	int fallback_user;
	/* strict refuses the session when the identity could not be recorded,
	 * rather than letting the login proceed unidentified.
	 *
	 * Off by default, which keeps the module's stated philosophy: a machine
	 * where wdog is not running should still be one people can log in to. But
	 * the permissive default has a sharp edge worth an option — a FULL session
	 * map fails exactly like a missing one, and from then on every login is
	 * unidentified and every employeeName-scoped rule silently stops matching.
	 * On a host where those rules are the control, `strict` turns that silent
	 * fail-open into a refused login, which is loud and recoverable. */
	int strict;
	/* origin overrides what classify_origin() would infer, and is how a stack
	 * the built-in table has never heard of gets classified: `origin=scheduled`
	 * in a site-local batch runner's stack. ORIGIN_UNKNOWN here means "no
	 * override given", which is why it cannot itself be selected by name — a
	 * stack that wants a session left unclassified simply omits the module. */
	uint32_t origin;
	/* The raw origin= argument, kept only so a name that matched nothing can
	 * be named back at the operator. Without it a typo is indistinguishable
	 * from no option at all — the stack would look configured and quietly
	 * classify nothing. */
	const char *origin_arg;
	/* origin_only makes the identity OPTIONAL rather than absent: the session
	 * is never refused for want of a name — not by the check below, not by
	 * `strict` — and a stack carrying it records what it has.
	 *
	 * This exists because the stacks that most need the origin axis are exactly
	 * the ones with nobody to name. A cron job has no person behind it, so the
	 * module's usual demand ("say who this is or the login is refused") is not
	 * a safety property there but an outage: dropping this module into
	 * /etc/pam.d/crond without this option stops every cron job on the host.
	 *
	 * It relaxes the requirement and NOTHING else. A name that is there is
	 * still recorded, which matters more than it looks: the GDM setup in
	 * docs/employee-pam.md puts this module in /etc/pam.d/systemd-user
	 * precisely so that session gets a name, and that stack also wants
	 * origin=service. Discarding a name here would quietly undo it. So the two
	 * compose — `origin=service origin_only fallback=user` names the session
	 * when PAM can and stays silent when it cannot.
	 *
	 * When no name is available the record carries an empty employee_name,
	 * which resolves in the kernel exactly as an unrecorded session does —
	 * EMPLOYEE_ID_ANY, so only rules naming nobody apply. The employee axis is
	 * therefore unchanged in both meaning and effect; the only thing gained is
	 * the origin. */
	int origin_only;
};

/* Names for the origin= option. ORIGIN_UNKNOWN is deliberately absent: the
 * option's job is to state an answer, and "unknown" is what its absence already
 * means. */
static const struct { const char *name; uint32_t origin; } origin_names[] = {
	{ "remote",    ORIGIN_REMOTE },
	{ "console",   ORIGIN_CONSOLE },
	{ "scheduled", ORIGIN_SCHEDULED },
	{ "service",   ORIGIN_SERVICE },
};

/* PAM service name -> origin, consulted when no origin= option was given.
 *
 * A fallback, not the mechanism. These are the /etc/pam.d/ file names RHEL 9
 * ships, and a distro is free to rename them or a site to invent its own — so a
 * miss here is expected and costs only ORIGIN_UNKNOWN, never a wrong answer.
 * The remedy for a miss is an origin= option in that stack, and the way an
 * operator finds out they need one is service= on the audit line naming
 * something this table does not list.
 *
 * su and sudo are absent on purpose, and their absence is not an oversight:
 * neither runs pam_loginuid, so neither opens an audit session, so this module
 * has nothing to key on and is not installed in those stacks. A session's
 * origin survives su and sudo untouched, exactly as its login uid does. */
static const struct { const char *service; uint32_t origin; } origin_table[] = {
	{ "sshd",           ORIGIN_REMOTE },
	/* THE ENTRY MOST WORTH UNDERSTANDING. "remote" is util-linux login(1)'s
	 * service name when it is started with -h, which is what in.telnetd (and
	 * rlogind) does — telnet-server ships no PAM stack of its own and delegates
	 * the whole login to /bin/login. So a telnet login reads /etc/pam.d/remote
	 * and never touches /etc/pam.d/login.
	 *
	 * That split is the reason this table can tell a telnet session from a
	 * console one at all: the same binary serves both, and the ONLY thing that
	 * distinguishes them here is which of its two service names it started PAM
	 * with. Putting the module in /etc/pam.d/login and expecting telnet to be
	 * covered is the mistake this entry exists to make survivable — it isn't
	 * covered, and without this entry a telnet session that somehow lost its
	 * PAM_RHOST would fall through to ORIGIN_UNKNOWN rather than to console. */
	{ "remote",         ORIGIN_REMOTE },
	/* FTP daemons. "vsftpd" is what RHEL's /etc/vsftpd/vsftpd.conf sets
	 * pam_service_name to; "ftp" is vsftpd's own compiled-in default, so a host
	 * that never edited that line lands there instead. Both are listed because
	 * which one applies is a config question, not a distro question.
	 *
	 * Listing them changes nothing unless vsftpd is also built and configured to
	 * open a PAM session — session_support defaults to NO, and with it off
	 * vsftpd never calls pam_open_session, so no session module runs at all.
	 * See docs/rules-session-origin.md; that is a bigger problem than the origin
	 * axis, because pam_loginuid.so is a session module too. */
	{ "vsftpd",         ORIGIN_REMOTE },
	{ "ftp",            ORIGIN_REMOTE },
	{ "proftpd",        ORIGIN_REMOTE },
	{ "pure-ftpd",      ORIGIN_REMOTE },
	/* login(1) WITHOUT -h: the local console. See the "remote" note above for
	 * why these two are the same program and must not be the same origin. */
	{ "login",          ORIGIN_CONSOLE },
	{ "gdm-password",   ORIGIN_CONSOLE },
	{ "gdm-autologin",  ORIGIN_CONSOLE },
	{ "gdm-launch-environment", ORIGIN_CONSOLE },
	{ "lightdm",        ORIGIN_CONSOLE },
	{ "xdm",            ORIGIN_CONSOLE },
	{ "crond",          ORIGIN_SCHEDULED },
	{ "atd",            ORIGIN_SCHEDULED },
	{ "systemd-user",   ORIGIN_SERVICE },
	{ "runuser",        ORIGIN_SERVICE },
	{ "runuser-l",      ORIGIN_SERVICE },
};

/* Where this session came from, decided in four steps and in this order:
 *
 *   1. the origin= option, which an operator wrote in this very stack and which
 *      therefore outranks anything this module could infer;
 *   2. the built-in table above, keyed on PAM_SERVICE;
 *   3. a non-empty PAM_RHOST, which means somebody reached this host over a
 *      network whatever the service is called;
 *   4. ORIGIN_UNKNOWN.
 *
 * Step 3 is last among the inferences rather than first because it is the
 * weaker signal of the two: a service in the table is a definite statement about
 * what kind of thing this is, while rhost only says the connection came from
 * somewhere else. They agree on sshd, and where they could disagree the named
 * service is what an operator would expect to win.
 *
 * Nothing here can fail. An unset PAM item, a service name nobody has heard of,
 * a truncated rhost — every one of them lands on ORIGIN_UNKNOWN, which the
 * kernel side treats as "matches only rules that constrain no origin". Failing
 * to a value that constrains nothing is the same direction the employee axis
 * fails in, and for the same reason: a login this module cannot classify must
 * not become a login that silently trips every origin-scoped deny rule on the
 * host. */
static uint32_t classify_origin(const struct options *o, const char *service,
				const char *rhost)
{
	if (o->origin != ORIGIN_UNKNOWN)
		return o->origin;
	if (service && *service) {
		for (size_t i = 0; i < sizeof(origin_table) / sizeof(origin_table[0]); i++)
			if (!strcmp(service, origin_table[i].service))
				return origin_table[i].origin;
	}
	if (rhost && *rhost)
		return ORIGIN_REMOTE;
	return ORIGIN_UNKNOWN;
}

static const char *origin_str(uint32_t origin)
{
	for (size_t i = 0; i < sizeof(origin_names) / sizeof(origin_names[0]); i++)
		if (origin_names[i].origin == origin)
			return origin_names[i].name;
	return "unknown";
}

/* A PAM item as a string, never NULL. pam_get_item leaves the pointer untouched
 * on failure and can also hand back a NULL for an item that was simply never
 * set, so both are folded into the empty string here — the callers treat "not
 * set" and "set to nothing" identically. */
static const char *item_str(pam_handle_t *pamh, int item)
{
	const void *v = NULL;

	if (pam_get_item(pamh, item, &v) != PAM_SUCCESS || !v)
		return "";
	return (const char *)v;
}

static void parse_options(struct options *o, int argc, const char **argv)
{
	o->map_path = DEFAULT_MAP_PATH;
	o->env_name = DEFAULT_ENV_NAME;
	o->debug = 0;
	o->fallback_user = 0;
	o->strict = 0;
	o->origin = ORIGIN_UNKNOWN;
	o->origin_arg = NULL;
	o->origin_only = 0;
	for (int i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "map=", 4))
			o->map_path = argv[i] + 4;
		else if (!strncmp(argv[i], "env=", 4))
			o->env_name = argv[i] + 4;
		else if (!strcmp(argv[i], "debug"))
			o->debug = 1;
		else if (!strcmp(argv[i], "fallback=user"))
			o->fallback_user = 1;
		else if (!strcmp(argv[i], "strict"))
			o->strict = 1;
		else if (!strcmp(argv[i], "origin_only"))
			o->origin_only = 1;
		else if (!strncmp(argv[i], "origin=", 7)) {
			/* An unrecognised name leaves o->origin at ORIGIN_UNKNOWN,
			 * so classify_origin falls through to the table and the
			 * session is still classified as well as it can be. The
			 * typo is reported at open_session, which has a pam handle
			 * to report it through; origin_arg is what survives to
			 * there to be named. */
			o->origin_arg = argv[i] + 7;
			for (size_t j = 0; j < sizeof(origin_names) / sizeof(origin_names[0]); j++)
				if (!strcmp(o->origin_arg, origin_names[j].name))
					o->origin = origin_names[j].origin;
		}
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

/* The wall clock now, in nanoseconds since the epoch — the moment this login is
 * being opened, which is the closest thing to a login time anything on the host
 * knows exactly.
 *
 * Zero on failure, which is deliberately the same value an older module's record
 * carries: wdog reads zero as "not recorded" and falls back to deriving the time
 * from /proc. So there is nothing to report and nothing to refuse here. In
 * practice clock_gettime(CLOCK_REALTIME) is a vDSO call that cannot fail with a
 * valid clock id and a valid pointer; the check is belt and braces. */
static uint64_t now_realtime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options o;
	struct session_identity id;
	union bpf_attr attr;
	const char *name, *service, *rhost;
	uint32_t origin;
	long sid, uid;
	uint32_t key;
	int fd;

	(void)flags;
	parse_options(&o, argc, argv);

	service = item_str(pamh, PAM_SERVICE);
	rhost = item_str(pamh, PAM_RHOST);
	origin = classify_origin(&o, service, rhost);
	/* A name that matched nothing. Worth LOG_ERR rather than a debug line: the
	 * stack LOOKS configured, and the only other symptom is origin-scoped rules
	 * quietly not matching a session an operator believes they classified. */
	if (o.origin_arg && o.origin == ORIGIN_UNKNOWN)
		pam_syslog(pamh, LOG_ERR,
			   "origin=%s names no known origin (remote, console, scheduled, service); falling back to the service name",
			   o.origin_arg);

	name = pam_getenv(pamh, o.env_name);
	if ((!name || !*name) && o.fallback_user) {
		const char *user = NULL;

		if (pam_get_item(pamh, PAM_USER, (const void **)&user) == PAM_SUCCESS)
			name = user;
	}
	/* origin_only makes the name optional, so a missing one is not a failure
	 * here — it is the expected state on a crond or atd stack. A name that IS
	 * present still gets recorded below; see struct options::origin_only. */
	if ((!name || !*name) && !o.origin_only) {
		/* Nobody said who this is, so refuse the session: an account reached
		 * this way would run entirely outside the per-person policy, which is
		 * the whole reason the module is installed. LOG_ERR unconditionally,
		 * not under debug — with `required` this is now the reason a login was
		 * turned away, and with `optional` it is a stack that silently records
		 * nobody. Both need to be visible without turning debug on. */
		pam_syslog(pamh, LOG_ERR,
			   "%s is unset; refusing the session (the module that sets it must run before pam_wood.so; use `optional` here to let such logins through unidentified, or `origin_only` in a stack with nobody to name, such as crond)",
			   o.env_name);
		/* Best effort: sshd relays this to the client on most builds, and where
		 * it does not, the syslog line above is what remains. Deliberately says
		 * nothing about which variable or module is missing — that is an
		 * operator's business, not the person being turned away. */
		pam_error(pamh, "Login denied: this account requires an identified user.");
		return PAM_SESSION_ERR;
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
		/* This line is worth reading twice. It is what an operator sees when
		 * wdog is simply not running — and it is ALSO what they see when an
		 * attacker has deleted the pin to switch the employee axis off, because
		 * from here the two are indistinguishable. `strict` is what lets a host
		 * refuse to guess. */
		pam_syslog(pamh, LOG_WARNING, "opening %s: %m (is wdog running?)", o.map_path);
		/* origin_only never refuses. A stack carrying it has nobody to
		 * identify, so there is no identity requirement for `strict` to
		 * enforce — and refusing here would stop cron on a host where the only
		 * thing wrong is that wdog is not running. */
		if (o.strict && !o.origin_only) {
			pam_error(pamh, "Login denied: this account requires an identified user.");
			return PAM_SESSION_ERR;
		}
		return PAM_SUCCESS;
	}

	/* memset first, and note that this is required rather than tidy: the kernel
	 * uses this name as a fixed-width hash key to look up the employee id its
	 * rules carry, and a hash key is compared as a block of bytes. Anything left
	 * after the terminator would hash to something no rule knows, and the login
	 * would silently go unidentified. strncpy pads to its bound for the same
	 * reason.
	 *
	 * It also zero-fills service and rhost, which matters for a second reason:
	 * this struct is 176 bytes of stack that the kernel copies WHOLE, so any
	 * byte left unwritten here is a byte of this function's frame published
	 * into a map. */
	memset(&id, 0, sizeof(id));
	/* One byte short of each field, so every string is always NUL-terminated. A
	 * longer employee name is truncated here and simply will not equal any rule
	 * — the loader rejects rules above the same bound, so the two agree. A
	 * truncated service or rhost only shortens a log line; nothing matches on
	 * them. Under origin_only name may be absent entirely, which leaves the
	 * memset's zeros in place — an empty name, resolving as an unidentified
	 * session does. */
	if (name && *name)
		strncpy(id.employee_name, name, EMPLOYEE_NAME_LEN - 1);
	strncpy(id.service, service, SESSION_SERVICE_LEN - 1);
	strncpy(id.rhost, rhost, SESSION_RHOST_LEN - 1);
	id.login_uid = (uint32_t)uid;
	id.origin = origin;
	id.login_time_ns = now_realtime_ns();
	key = (uint32_t)sid;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(unsigned long)&key;
	attr.value = (uint64_t)(unsigned long)&id;
	attr.flags = BPF_ANY;
	if (bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0) {
		/* E2BIG is the map being full: sessions have accumulated faster than
		 * they were reaped. Worth naming, because from here on no new login
		 * can be identified at all. */
		if (errno == E2BIG)
			pam_syslog(pamh, LOG_ERR,
				   "%s is full; new logins cannot be identified until entries are freed",
				   o.map_path);
		else
			pam_syslog(pamh, LOG_INFO, "recording session %ld: %m", sid);
		if (o.strict && !o.origin_only) {
			close(fd);
			pam_error(pamh, "Login denied: this account requires an identified user.");
			return PAM_SESSION_ERR;
		}
	} else if (o.debug) {
		pam_syslog(pamh, LOG_INFO,
			   "session %ld (uid %ld) recorded as %s, origin %s (service %s, rhost %s)",
			   sid, uid, id.employee_name, origin_str(id.origin),
			   id.service, id.rhost);
	}
	close(fd);
	return PAM_SUCCESS;
}

/* Mark the session closed. NOT delete it — that distinction is the whole of this
 * function, and it is worth stating why here rather than only in door/.
 *
 * The audit session id outlives the login. A process that was in this session
 * carries task->sessionid until it exits, whatever happens to sshd, and plenty
 * of them are DESIGNED to outlive it: a VS Code or JetBrains remote server whose
 * bootstrap ssh disconnects seconds after launching it, anything under nohup or
 * setsid, a shell inside tmux or screen. Deleting the record here took both user
 * axes away from exactly those processes — employee and origin went blank for
 * the rest of their lives, and rules naming either silently stopped matching the
 * longest-lived and most interesting work on the host.
 *
 * So the record lingers, carrying SESSION_CLOSED, and wdog's reaper removes it
 * once the session has no live process left (cmd/wdog/session.go). It already
 * did that for sessions that never reached this function at all; the only change
 * on that side is that it now stays quiet when the flag says a logout was
 * already reported.
 *
 * BPF_EXIST rather than BPF_ANY, and it is load-bearing twice over. It refuses
 * to resurrect a record the reaper deleted between the lookup and the update —
 * the two are not atomic and cannot be — and, because open_session passes
 * BPF_ANY, the flag is what lets the kernel object tell a close from an open now
 * that both are BPF_MAP_UPDATE_ELEM. See self_session_record() in
 * door/self_check.h; without it every logout on the host reports as a login. */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options o;
	union bpf_attr attr;
	struct session_identity id;
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
	attr.value = (uint64_t)(unsigned long)&id;
	/* The lookup fills all 176 bytes, so what goes back is what was recorded at
	 * login with one bit added — no field is rewritten from this frame, and the
	 * name keeps the zero padding the kernel hashes it on.
	 *
	 * ENOENT means there was no record: an open_session that found no name, a
	 * stack this module is not installed in, or wdog's reaper got there first.
	 * None is worth a log line. */
	if (bpf(BPF_MAP_LOOKUP_ELEM, &attr) < 0) {
		if (errno != ENOENT)
			pam_syslog(pamh, LOG_WARNING, "reading session %ld: %m", sid);
		close(fd);
		return PAM_SUCCESS;
	}
	id.origin |= SESSION_CLOSED;
	attr.flags = BPF_EXIST;
	if (bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0 && errno != ENOENT)
		pam_syslog(pamh, LOG_WARNING, "closing session %ld: %m", sid);
	else if (o.debug)
		pam_syslog(pamh, LOG_DEBUG,
			   "session %ld closed; record kept until its last process exits", sid);
	close(fd);
	return PAM_SUCCESS;
}
