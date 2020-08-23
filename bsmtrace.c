/*-
 * Copyright (c) 2007 Aaron L. Meihm
 * Copyright (c) 2007 Christian S.J. Peron
 * All rights reserved.
 *
 * $Id$
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "includes.h"

static int	daemonized;	/* daemonized or not? */
int	audit_pipe_fd;

/*
 * If we are going to be daemonized, write out a pid file to
 * /var/run/bsmtrace.pid.  We might want to change this in the
 * future when we add more privilege dropping code.
 */
void
bsmtrace_write_pidfile(char *pidfile)
{
	char pidbuf[32];
	int fd;

	fd = open(pidfile, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (fd < 0)
		bsmtrace_fatal("open pid file failed");
	(void) sprintf(pidbuf, "%d", getpid());
	if (write(fd, pidbuf, strlen(pidbuf)) < 0)
		bsmtrace_fatal("write pid file faled");
	(void) close(fd);
}


void
bsmtrace_fatal(char *fmt, ...)
{
	char fmtbuf[1024];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, ap);
	va_end(ap);
	bsmtrace_warn("fatal: %s", fmtbuf);
	exit(1);
}

/*
 * bsmtrace error reporting, if flag is non-zero this error is treated as fatal
 * and a clean exit will occur, otherwise we report this error as a warning and
 * return.
 */
void
bsmtrace_warn(char *fmt, ...)
{
	char fmtbuf[1024];
	va_list ap;
	int pri;

	pri = LOG_WARNING;
	va_start(ap, fmt);
	(void) vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, ap);
	va_end(ap);
	syslog(pri, "%s", fmtbuf);
	/*
	 * If we are not yet a daemon, we also write the error message
	 * to stderr.
	 */
	if (!daemonized)
		(void) fprintf(stderr, "warning: %s\n", fmtbuf);
	return;
}

void
debug_printf(char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	if (!opts.dflag)
		return;
	va_start(ap, fmt);
	(void) memset(buf, 0, sizeof(buf));
	(void) vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "debug: %s", buf);
	(void) fflush(stderr);
}

void
bsmtrace_handle_sigint(int sig)
{

	if (audit_pipe_fd != 0) {
		(void) fputs("\n", stderr);
		pipe_report_stats(audit_pipe_fd);
	}
	exit(1);
}

void
set_default_settings(struct g_conf *gc)
{

	gc->aflag = DEFAULT_AUDIT_TRAIL;
	gc->fflag = DEFAULT_BSMTRACE_CONFFILE;
	gc->pflag = DEFAULT_BSMTRACE_PIDFILE;
	openlog("bsmtrace", LOG_NDELAY | LOG_PID, LOG_AUTH | LOG_ALERT);
}

static void
bsmtrace_seed(void)
{
	unsigned long seed;
	int fd;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0)
		bsmtrace_fatal("open random device failed");
	if (read(fd, &seed, sizeof(seed)) != sizeof(seed))
		bsmtrace_fatal("read random device failed");
	srandom(seed);
	(void) close(fd);
}

int
main(int argc, char *argv[])
{
	int ret, fd;
	char ch;

	bsmtrace_seed();
	(void) signal(SIGCHLD, SIG_IGN); /* Ignore dying children */
	(void) signal(SIGINT, bsmtrace_handle_sigint);
	set_default_settings(&opts);
	while ((ch = getopt(argc, argv, "Fa:Bbdf:hil:np:v")) != -1) {
		switch (ch) {
		case 'B':
			opts.Bflag = 1;
			break;
		case 'F':
			opts.Fflag = 1;
			break;
		case 'a':
			opts.aflag = optarg;
			break;
		case 'b':
			opts.bflag = 1;
			break;
		case 'd':
			opts.dflag = 1;
			break;
		case 'f':
			opts.fflag = optarg;
			break;
		case 'l':
			opts.lflag = optarg;
			break;
		case 'n':
			opts.nflag = 1;
			break;
		case 'p':
			opts.pflag = optarg;
			break;
		case 'v':
			(void) fprintf(stderr, "%s\n", BSMTRACE_VERSION);
			exit(0);
		case 'h':
		default:
			usage(argv[0]);
			/* NOTREACHED */
		}
	}
	/*
	 * Reading configuration isn't a prerequisite for init'ing the logdir, so do
	 * this now.  The configuration may try to setup files within the logdir.
	 */
	log_init_dir();
	conf_load(opts.fflag);
	if (opts.nflag != 0)
		return (0);
	if (!opts.Fflag) {
		ret = fork();
		if (ret == -1)
			bsmtrace_fatal("fork failed: %s", strerror(errno));
		if (ret != 0)
			exit(0);
		/*
		 * Redirect STDOUT, STDERR, and STDIN to /dev/null since we are
		 * operating in daemon mode.
		 */
		fd = open("/dev/null", O_RDWR);
		if (fd < 0)
			bsmtrace_fatal("open(/dev/null): %s", strerror(errno));
		(void) dup2(fd, STDIN_FILENO);
		(void) dup2(fd, STDOUT_FILENO);
		(void) dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void) close(fd);
		if (setsid() < 0)
			bsmtrace_fatal("setsid failed: %s",
			    strerror(errno));
		bsmtrace_write_pidfile(opts.pflag);
		daemonized = 1;
	}
	bsm_loop(opts.aflag);
	return (0);
}

void
usage(char *progname)
{

	(void) fprintf(stderr,
	    "usage: %s [-Fbdhv] [-a trail] [-f config_file] [-p pid_file]\n\n"
	    "  -a trail          Audit trail to be examined.\n"
	    "  -b                Dump the last BSM record which results in a\n"
	    "  -B                Log BSM records associated with the alert\n"
	    "                    sequence match to stdout.\n"
	    "  -d                Print debugging messages.\n"
	    "  -f config_file    Location of config file.\n"
	    "  -F                Run program in foreground.\n"
	    "  -h                Print this help message.\n"
	    "  -l                Logging directory\n"
	    "  -n                Parse the configuration and exit\n"
	    "  -p pid_file       Location of pid file.\n"
	    "  -v                Print version and exit.\n"
	    , progname);
	exit(0);
}
