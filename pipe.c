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
#include <sys/types.h>

#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>

#include "includes.h"

#ifdef AUDITPIPE_GET_DROPS

static int	ap_cur_drop_cnt;

void
pipe_analyze_loss(int pipefd)
{
	struct pipe_stats aps;
	unsigned int cur_qlim, max_qlim;

	pipe_get_stats(pipefd, &aps);
	/*
	 * If there has been no change in the drop count since the last time
	 * we collected the statistics, return because there is nothing to
	 * worry about.
	 */
	if (aps.ap_drops == ap_cur_drop_cnt)
		return;
	bsmtrace_warn(
	    "audit pipe dropped a total of %u records (%u) since last interval",
	    aps.ap_drops, aps.ap_drops - ap_cur_drop_cnt);
	ap_cur_drop_cnt = aps.ap_drops;
	/*
	 * There has been some additional loss, so attempt to increase the
	 * queue length to try to keep up.  In order to conserve memory,
	 * we try to double the queue size each time.  If we run up against
	 * the maximum queue limit, simply return.
	 */
	if (ioctl(pipefd, AUDITPIPE_GET_QLIMIT, &cur_qlim) < 0)
		bsmtrace_fatal("AUDITPIPE_GET_QLIMIT: %s",
		    strerror(errno));
	if (ioctl(pipefd, AUDITPIPE_GET_QLIMIT_MAX, &max_qlim) < 0)
		bsmtrace_fatal("AUDITPIPE_GET_QLIMIT_MAX: %s",
		    strerror(errno));
	if (cur_qlim == max_qlim)
		return;
	assert(cur_qlim <= max_qlim);
	cur_qlim *= 2;
	if (ioctl(pipefd, AUDITPIPE_SET_QLIMIT, &cur_qlim) < 0)
		bsmtrace_fatal("AUDITPIPE_SET_QLIMIT: %s",
		    strerror(errno));
	bsmtrace_warn("resized queue to %u records", cur_qlim);
}

void
pipe_get_stats(int pipefd, struct pipe_stats *aps)
{

	assert(aps != NULL);
	if (ioctl(pipefd, AUDITPIPE_GET_READS, &aps->ap_reads) < 0)
		bsmtrace_fatal("AUDITPIPE_GET_READS: %s",
		    strerror(errno));
	if (ioctl(pipefd, AUDITPIPE_GET_DROPS, &aps->ap_drops) < 0)
		bsmtrace_fatal("AUDITPIPE_GET_DROPS: %s",
		    strerror(errno));
}

void
pipe_report_stats(int pipefd)
{
	struct pipe_stats aps;

	assert(pipefd > 0);
	pipe_get_stats(pipefd, &aps);
	if (opts.Fflag)
		bsmtrace_warn(
		    "audit record drops %" PRIu64 "\n"
		    "audit record reads %" PRIu64 "\n",
		    aps.ap_drops, aps.ap_reads);
	else
		syslog(LOG_AUTH | LOG_INFO,
		    "audit record drops=%" PRIu64 " reads=%" PRIu64 "",
		    aps.ap_drops, aps.ap_reads);
}
#endif	/* AUDITPIPE_GET_DROPS */
