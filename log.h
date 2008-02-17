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
#ifndef LOG_H_
#define LOG_H_

TAILQ_HEAD(, logchannel) log_head;

enum {
	LOG_CHANNEL_NOP,
	LOG_CHANNEL_SYSLOG,
	LOG_CHANNEL_BSM,
	LOG_CHANNEL_STDERR
};

struct logchannel {
	int	 log_type;
	char	*log_name;
	union {
		int	 syslog_pri;
		char	*bsm_log_dir;
	} log_data;
	TAILQ_ENTRY(logchannel) log_glue;
	void (*log_handler)(struct logchannel *, struct bsm_sequence *,
	    struct bsm_record_data *);
};

int	 log_chan_type(char *);
int	 log_syslog_encode(char *);
struct logchannel
	*log_lookup_channel(char *);
int	 log_bsm_stderr(struct logchannel *, struct bsm_sequence *,
	     struct bsm_record_data *);
void 	*log_chan_handler(char *);
int	 log_bsm_file(struct logchannel *, struct bsm_sequence *,
	     struct bsm_record_data *);
#endif /* LOG_H_ */
