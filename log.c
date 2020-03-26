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
#define SYSLOG_NAMES
#include "includes.h"
#undef SYSLOG_NAMES

int rotate_log;

void
log_init_dir(void)
{
	char logpath[128];
	struct stat sb;
	mode_t flags;

	if (opts.lflag == NULL)
		return;
	if (opts.Bflag != 0 && opts.lflag == NULL) {
		bsmtrace_fatal("-l directory must be specified for -B\n");
	}
	if (stat(opts.lflag, &sb) == -1) {
		bsmtrace_fatal("stat: logging directory: %s: %s\n",
		    opts.lflag, strerror(errno));
	}
	if ((sb.st_mode & S_IFDIR) == 0) {
		bsmtrace_fatal("%s: is not a directory\n", opts.lflag);
	}
	if (access(opts.lflag, W_OK | R_OK | X_OK) != 0) {
		bsmtrace_fatal("%s: invalid permissions\n", opts.lflag);
	}
	opts.log_dir_fd = open(opts.lflag, O_RDONLY | O_DIRECTORY);
	if (opts.log_dir_fd == -1) {
		bsmtrace_fatal("failed to open logging directory: %s\n",
		    strerror(errno));
	}
	flags = S_IWUSR | S_IRUSR;
	opts.logfd = openat(opts.log_dir_fd, "bsmtrace.log", O_APPEND | O_WRONLY | O_CREAT, flags);
	if (opts.logfd == -1) {
		bsmtrace_fatal("open: %s failed: %s\n", logpath,
		    strerror(errno));
	}
	debug_printf("logging directory and file initialized");
}

static char *
parse_bsm_generic(struct bsm_sequence *bs, struct bsm_record_data *br)
{
	char 	 message[128 + NAME_MAX];
	char	*basename;
	u_int subj;

	if (strcmp(opts.aflag, "-") == 0)
		basename = "stdin";
	else {
		basename = strrchr(opts.aflag, '/');
		basename = (basename == NULL) ? opts.aflag : basename + 1;
	}

	if ((bs->bs_seq_flags & BSM_SEQUENCE_PARENT) != 0) {
		subj = bsm_get_subj(bs, br);
		bs->bs_first_match = br->br_sec;
	} else
		subj = bs->bs_subj.bs_dyn_subj;

	(void) snprintf(message, sizeof(message),
	    "%d.%d state machine: %s subject: auid %d "
	    "completed: duration %d seconds priority: %d "
	    "source: %s\n",
	    br->br_sec, br->br_usec, bs->bs_label,
	    subj, br->br_sec - bs->bs_first_match, bs->bs_priority, basename);
	return (strdup(message));
}

int
log_bsm_stderr(struct bsm_sequence *bs, struct bsm_record_data *br)
{
	char *ptr;

	ptr = parse_bsm_generic(bs, br);
	if (ptr == NULL)
		return (-1);
	(void) fputs(ptr, stderr);
	free(ptr);
	return (0);
}

int
log_bsm_syslog(struct bsm_sequence *bs, struct bsm_record_data *br)
{
	char *ptr;

	ptr = parse_bsm_generic(bs, br);
	if (ptr == NULL)
		return (-1);
	/*
	 * NB: re-visit the facility and priority here.
	 */
	syslog(LOG_AUTH | LOG_NOTICE, "%s", ptr);
	free(ptr);
	return (0);
}

int
log_bsm_txt_file(struct bsm_sequence *bs, struct bsm_record_data *br)
{
	ssize_t cc;
	char *ptr;
	size_t s;
	mode_t flags;

	if (rotate_log == 1) {
		close(opts.logfd);
		flags = S_IWUSR | S_IRUSR;
		opts.logfd = openat(opts.log_dir_fd, "bsmtrace.log",
		    O_APPEND | O_WRONLY | O_CREAT, flags);
		if (opts.logfd == -1) {
			bsmtrace_fatal("failed to rotate log: %s",
			    strerror(errno));
		}
		rotate_log = 0;
	}
	ptr = parse_bsm_generic(bs, br);
	if (ptr == NULL)
		return (-1);
	s = strlen(ptr);
	cc = write(opts.logfd, ptr, s);
	if (cc == -1) {
		bsmtrace_fatal("failed to write log data: %s\n",
		    strerror(errno));
		free(ptr);
		return (-1);
	}
	if (cc != s) {
		bsmtrace_warn("partial write for log data?\n");
	}
	debug_printf("wrote %lld bytes to logfile\n", cc);
	free(ptr);
	return (0);
}

int
log_bsm_file(struct bsm_sequence *bs, struct bsm_record_data *br)
{
	char path[MAXPATHLEN];
	int fd;
	struct bsm_state *bm;
	char *src_basename;

	if (strcmp(opts.aflag, "-") == 0)
		src_basename = "stdin";
	else {
		src_basename = strrchr(opts.aflag, '/');
		src_basename = (src_basename == NULL) ? opts.aflag : src_basename + 1;
	}
	if (mkdirat(opts.log_dir_fd, bs->bs_label, S_IRWXU) < 0) {
		if (errno != EEXIST) {
			bsmtrace_fatal("mkdirat failed: %s: %s", bs->bs_label,
			    strerror(errno));
		}
	} 
	(void) sprintf(path, "%s/%d.%d.%lu",
	    bs->bs_label, br->br_sec, br->br_usec, random());
	fd = openat(opts.log_dir_fd, path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0)
		bsmtrace_fatal("openat: %s: %s", path, strerror(errno));
	/*
	 * The logic here becomes a bit complex.  We need to check to see if
	 * this is a single state sequence, and if it is, log the BSM record
	 * data attached to the bsm_record_data structure.  Otherwise, the we
	 * are dealing with a dynamic sequence, and the records are attached to
	 * each individual state.
	 */
	syslog(LOG_AUTH | LOG_NOTICE,
	    "%u.%u sequence %s match evidence file: %s source: %s",
	    br->br_sec, br->br_usec,
	    bs->bs_label,
	    path,
	    src_basename);
	if ((bs->bs_seq_flags & BSM_SEQUENCE_PARENT) != 0) {
		if (write(fd, br->br_raw, br->br_raw_len) < 0)
			bsmtrace_fatal("write failed");
		(void) close(fd);
		return (0);
	}
	TAILQ_FOREACH(bm, &bs->bs_mhead, bm_glue)
		if (write(fd, bm->bm_raw, bm->bm_raw_len) < 0)
			bsmtrace_fatal("write failed");
	(void) close(fd);
	return (0);
}
