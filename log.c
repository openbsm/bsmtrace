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

int
log_bsm_syslog(struct logchannel *lc, struct bsm_sequence *bs,
    struct bsm_record_data *br);

static const struct _logchannel_type {
	char	*lc_str;
	int	 lc_type;
	int	(*func)(struct logchannel *, struct bsm_sequence *,
		    struct bsm_record_data *);
} logchannel_tab[] = {
	{ "bsm",	LOG_CHANNEL_BSM, log_bsm_file },
	{ "syslog",	LOG_CHANNEL_SYSLOG, log_bsm_syslog },
	{ "stderr",	LOG_CHANNEL_STDERR, log_bsm_stderr },
	{ NULL,		0, NULL }
};

char *
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
log_bsm_stderr(struct logchannel *lc, struct bsm_sequence *bs,
    struct bsm_record_data *br)
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
log_bsm_syslog(struct logchannel *lc, struct bsm_sequence *bs,
    struct bsm_record_data *br)
{
	char *ptr;

	ptr = parse_bsm_generic(bs, br);
	if (ptr == NULL)
		return (-1);
	syslog(lc->log_data.syslog_pri, "%s", ptr);
	free(ptr);
	return (0);
}

int
log_bsm_file(struct logchannel *lc, struct bsm_sequence *bs,
    struct bsm_record_data *br)
{
	char path[MAXPATHLEN], dir[MAXPATHLEN];
	struct stat sb;
	int fd, error;
	struct bsm_state *bm;
	char *src_basename;

	if (strcmp(opts.aflag, "-") == 0)
		src_basename = "stdin";
	else {
		src_basename = strrchr(opts.aflag, '/');
		src_basename = (src_basename == NULL) ? opts.aflag : src_basename + 1;
	}
	(void) snprintf(dir, MAXPATHLEN,
	    "%s/%s", lc->log_data.bsm_log_dir, bs->bs_label);
	error = stat(dir, &sb);
	if (error < 0 && errno == ENOENT) {
		if (mkdir(dir, S_IRWXU) < 0)
			bsmtrace_error(1, "mkdir failed");
	} else if (error < 0)
		bsmtrace_error(1, "stat failed");
	(void) sprintf(path, "%s/%d.%d.%lu",
	    dir, br->br_sec, br->br_usec, random());
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0)
		bsmtrace_error(1, "open: %s: %s", path, strerror(errno));
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
			bsmtrace_error(1, "write failed");
		(void) close(fd);
		return (0);
	}
	TAILQ_FOREACH(bm, &bs->bs_mhead, bm_glue)
		if (write(fd, bm->bm_raw, bm->bm_raw_len) < 0)
			bsmtrace_error(1, "write failed");
	(void) close(fd);
	return (0);
}

/*
 * The decode and pencode functions were ripped from the FreeBSD 6.2 logger(1)
 * code pretty much verbatim.
 */
static int
decode(char *name, CODE *codetab)
{
	CODE *c;

	if (isdigit(*name))
		return (atoi(name));
	for (c = codetab; c->c_name; c++)
		if (!strcasecmp(name, c->c_name))
			return (c->c_val);
	return (-1);
}

int
log_syslog_encode(char *s)
{
	int fac, lev;
	char *save;

	for (save = s; *s && *s != '.'; ++s);
	if (*s) {
		*s = '\0';
		fac = decode(save, facilitynames);
		if (fac < 0)
			return (-1);
		*s++ = '.';
	} else {
		fac = 0;
		s = save;
	}
	lev = decode(s, prioritynames);
	if (lev < 0)
		return (-1);
	return ((lev & LOG_PRIMASK) | (fac & LOG_FACMASK));
}

int
log_chan_type(char *string)
{
	const struct _logchannel_type *p;

	for (p = logchannel_tab; p->lc_str != NULL; p++)
		if (strcmp(string, p->lc_str) == 0)
			return (p->lc_type);
	return (-1);
}

void *
log_chan_handler(char *string)
{
	const struct _logchannel_type *p;

	for (p = logchannel_tab; p->lc_str != NULL; p++)
		if (strcmp(string, p->lc_str) == 0)
			return (p->func);
	return (NULL);
}

struct logchannel *
log_lookup_channel(char *string)
{
	struct logchannel *lc;

	TAILQ_FOREACH(lc, &log_head, log_glue) {
		if (strcmp(string, lc->log_name) == 0)
			return (lc);
	}
	return (NULL);
}
