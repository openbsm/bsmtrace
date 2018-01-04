/*
 * Copyright (c) 2016 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2003 Can Erkin Acar
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef __FreeBSD__
#include <sys/capsicum.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "includes.h"
#include "privsep.h"
#include "privsep_fdpass.h"

#include <stdarg.h>

volatile pid_t child_pid = -1;
int priv_fd = -1;
int priv_sep_on = 0;
int __real_open(const char *path, int flags, ...);

volatile sig_atomic_t gotsig_chld = 0;

/* Proto-types */
static void sig_pass_to_chld(int);
static void sig_chld(int);

static void
sig_chld(int sig)
{

	gotsig_chld = 1;
}

/* If priv parent gets a TERM or HUP, pass it through to child instead */
static void
sig_pass_to_chld(int sig)
{
	int oerrno;

	oerrno = errno;
	if (child_pid != -1)
		(void) kill(child_pid, sig);
	errno = oerrno;
}

static void
priv_setuid(void)
{
	struct passwd *pwd;

	/* NB: getuid check is not sufficient for but leave it for now */
	if (getuid() != 0)
		return;
	pwd = getpwnam(opts.uflag);
	if (pwd == NULL) {
		bsmtrace_error(1, "failed to get privsep uid\n");
	}
	/*
	 * Change the permissions associated with the logging directory.
	 */
	assert(opts.log_dir_fd != 0);
	if (fchown(opts.log_dir_fd, pwd->pw_uid, pwd->pw_gid) == -1) {
		bsmtrace_error(1, "unable to change logging direcotry ownership");
	}
	if (initgroups(opts.uflag, pwd->pw_gid) == -1) {
		bsmtrace_error(1, "initgroups failed: %s\n",
		    strerror(errno));
	}
	if (setgid(pwd->pw_gid) == -1) {
		bsmtrace_error(1, "setgid failed\n");
	}
	if (setuid(pwd->pw_uid) == -1) {
		bsmtrace_error(1, "setuid failed\n");
	}
}

static void
child_handle_signal(int sig)
{
	extern int rotate_log;

	switch (sig) {
	case SIGHUP:
		rotate_log = 1;
		debug_printf("caught SIGHUP: will rotate log on next write\n");
		break;
	/*
	 * Other signals?
	 */
	}
}

int
priv_init(void)
{
	int i, socks[2], cmd;

	for (i = 1; i < NSIG; i++)
		signal(i, SIG_DFL);
	/* Create sockets */
	if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		(void) fprintf(stderr, "socketpair: %s\n", strerror(errno));
		exit(1);
	}
	child_pid = fork();
	if (child_pid == -1) {
		(void) fprintf(stderr, "fork: %s\n", strerror(errno));
		exit(1);
	}
	if (child_pid == 0) {
		signal(SIGHUP, child_handle_signal);
		(void) close(socks[0]);
#ifdef __FreeBSD__
		priv_setuid();
		(void) fprintf(stdout, "Entering capability mode sandbox\n");
		if (cap_enter() == -1) {
			(void) fprintf(stderr, "cap_enter failed: %s\n",
			    strerror(errno));
			exit(1);
		}
#endif /* __FreeBSD__ */
#ifdef linux
		priv_setuid();
		(void) fprintf(stdout, "Entering seccomp BPF mode sandbox\n");
		seccomp_activate();
#endif /* linux */
#ifdef __APPLE__
		fprintf(stderr, "poor man's sandbox\n");
		if (chdir("/var/empty") == -1) {
			bsmtrace_error(1, "failed to chdir to /var/empty\n");
		}
		if (chroot(".") == -1) {
			bsmtrace_error(1, "failed to chroot unprivileged process\n");
		}
		priv_setuid();
#endif
		priv_fd = socks[1];
		priv_sep_on = 1;
		return 0;
	}
	/*
	 * Pass ALRM/TERM/HUP/INT/QUIT through to child, and accept CHLD
	 */
	signal(SIGALRM, sig_pass_to_chld);
	signal(SIGTERM, sig_pass_to_chld);
	signal(SIGHUP,  sig_pass_to_chld);
	signal(SIGINT,  sig_pass_to_chld);
	signal(SIGQUIT,  sig_pass_to_chld);
	signal(SIGCHLD, sig_chld);
	close(socks[1]);
	while (!gotsig_chld) {
		if (may_read(socks[0], &cmd, sizeof(int)))
			break;
		switch (cmd) {
		case PRIV_GET_CONF_FD:
			{
			int fd, ecode;

			fd = open(opts.fflag, O_RDONLY);
			if (fd == -1) {
				(void) fprintf(stderr, "config open: %s\n", strerror(errno));
				ecode = errno;
			}
			send_fd(socks[0], fd);
			if (fd == -1) {
				must_write(socks[0], &ecode, sizeof(ecode));
				break;
			}
			close(fd);
			printf("config fd sent\n");
			break;
			}
		case PRIV_GET_AUDITPIPE_FD:
			{
			int fd, ecode;

			fd = open(opts.aflag, O_RDONLY);
			if (fd == -1) {
				(void) fprintf(stderr, "error opening audit pipe: %s\n",
				    strerror(errno));
				ecode = errno;
			}
			send_fd(socks[0], fd);
			if (fd == -1) {
				must_write(socks[0], &ecode, sizeof(ecode));
				break;
			}
			close(fd);
			printf("audit pipe fd sent\n");
			break;
			}
		case PRIV_GET_LOGDIR_FD:
		default:
			(void) fprintf(stderr, "got request for unknown priv\n");
		}
	}
	_exit(1);
}

/*
 * Read all data or return 1 for error.
 */
int
may_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			return (1);
		default:
			pos += res;
		}
	}
	return (0);
}

/*
 * Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void
must_read(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = read(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}

/*
 * Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void
must_write(int fd, void *buf, size_t n)
{
	char *s = buf;
	ssize_t res, pos = 0;

	while (n > pos) {
		res = write(fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			_exit(0);
		default:
			pos += res;
		}
	}
}

/*
 * Functions to be used by the non-privleged process
 */

/*
 * Grab a file to the configuration file which was passed in on
 * the command line.
 */
FILE *
priv_config_open(void)
{
	FILE *fp;
	int cmd, s, e;

	cmd = PRIV_GET_CONF_FD;
	must_write(priv_fd, &cmd, sizeof(cmd));
	s = receive_fd(priv_fd);
	if (s == -1) {
		must_read(priv_fd, &e, sizeof(e));
		errno = e;
		return (NULL);
	}
	fp = fdopen(s, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, "fdopen failed: %s\n",
		    strerror(errno));
		exit(1);
	}
	return (fp);
}

/*
 * Grab a file descriptor for the auditpipe(4) itself
 */
FILE *
priv_auditpipe_open(void)
{
	int cmd, s, e;
	FILE *fp;

	cmd = PRIV_GET_AUDITPIPE_FD;
	must_write(priv_fd, &cmd, sizeof(cmd));
	s = receive_fd(priv_fd);
	if (s == -1) {
		must_read(priv_fd, &e, sizeof(e));
		errno = e;
		return (NULL);
	}
	fp = fdopen(s, "r");
	if (fp == NULL) {
		bsmtrace_error(0, "failed to open audit pipe: %s\n",
		    strerror(errno));
		exit(1);
	}
	return (fp);
}

/*
 * Get a file descriptor to the logging directory that was passed in
 * on the command line.  bsmtrace will be able to rotate log files
 * and create BSM dump files by way of openat(2).  This is a much
 * more safe alternative than giving bsmtrace access to the global
 * file system namespace.
 */
int
priv_get_logdir_fd(void)
{
	int cmd, s, e;

	cmd = PRIV_GET_LOGDIR_FD;
	must_write(priv_fd, &cmd, sizeof(cmd));
	s = receive_fd(priv_fd);
	if (s == -1) {
		must_read(priv_fd, &e, sizeof(e));
		errno = e;
		return (-1);
        }
	return (s);
}

