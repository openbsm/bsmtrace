/*-
 * Copyright (c) 2007 Aaron L. Meihm
 * Copyright (c) 2007 Christian S.J. Peron
 * All rights reserved.
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
#ifndef DEUCE_H_
#define	DEUCE_H_

#define	BSM_ARRAY_MAX	1024

typedef TAILQ_HEAD(, bsm_sequence) b_head_t;

enum {
	BSM_SCOPE_GLOBAL,
	BSM_SCOPE_PROCESS,
	BSM_SCOPE_SESSION,
	BSM_SCOPE_THREAD
};

enum {
	SET_TYPE_NOOP,
	SET_TYPE_AUCLASS,
	SET_TYPE_AUEVENT,
	SET_TYPE_AUID,
	SET_TYPE_EGID,
	SET_TYPE_EUID,
	SET_TYPE_PATH,
#ifdef PCRE
	SET_TYPE_PCRE,
#endif
	SET_TYPE_RGID,
	SET_TYPE_RUID,
	SET_TYPE_LOGCHANNEL
};

union array_data {
	int		value;
	char		*string;
#ifdef PCRE
	pcre		*pcre;
#endif
};

struct array {
	int		a_type;	/* Content type of a_data */
	int		a_negated;
#define INTEGER_ARRAY	1
#define STRING_ARRAY	2
#ifdef PCRE
#define PCRE_ARRAY	4
#endif
	size_t		a_cnt;
	size_t		a_size;
	union array_data *a_data;
};

/*
 * Member status values
 */
enum {
	EVENT_NOOP,
	EVENT_SUCCESS_OR_FAILURE,
	EVENT_SUCCESS,
	EVENT_FAILURE
};

/*
 * Temporary BSM storage set used during configuration file parsing.
 */
struct bsm_set {
	struct array		 bss_data;
	TAILQ_ENTRY(bsm_set)	 bss_glue;
	char			*bss_name;
	int			 bss_type;
	const char		*bss_file;
};
typedef	TAILQ_HEAD(, bsm_set)	bsm_set_head_t;

struct bsm_state {
	struct array	 bm_auditevent;
	struct array	 bm_objects;
	int		 bm_status;
	int		 bm_multiplier;
	int		 bm_event_type;
#define	BSM_STATE_EVENT_ANY		 0x00000001U
	u_int		 bm_event_flags;
	char		 bm_trig[8192];
	TAILQ_ENTRY(bsm_state)	bm_glue;
	caddr_t		 bm_raw;
	int		 bm_raw_len;
};

struct tailq;
struct bsm_sequence {
	char				*bs_label;
	u_int				 bs_subj_type;
#define	BSM_SEQUENCE_PARENT		 0x00000001U
#define BSM_SEQUENCE_DYNAMIC		 0x00000002U
#define	BSM_SEQUENCE_DESTROY		 0x00000004U
#define BSM_SEQUENCE_SUBJ_ANY		 0x00000008U
	u_int				 bs_seq_flags;
	union {
		struct array		 bs_par_subj;
		u_int			 bs_dyn_subj;
	} bs_subj;
	u_int				 bs_timeout;
	time_t				 bs_mtime;
	struct bsm_state		*bs_cur_state;
	TAILQ_HEAD(tailq, bsm_state)	 bs_mhead;
	TAILQ_ENTRY(bsm_sequence)	 bs_glue;
	struct bsm_sequence		*bs_par_sequence;
	u_int				 bs_first_match;
	int				 bs_priority;
	int				 bs_seq_scope;
	pid_t				 bs_seq_scope_data;
	int				 bs_seq_serial;
	int				 bs_seq_time_wnd;
	int				 bs_seq_time_wnd_prob;
	char				*bs_zonename;
	int				 bs_logfile;
};

/*
 * Define some special types for zonename: ZONENAME_NONE and ZONENAME_ANY.
 * These take advantage of non-printable characters to do the dirty work, which
 * works kind of like mmap(2) in that these will never occur in the input space.
 */
#define	ZONENAME_NONE		((char *)1)	/* Host-only. */
#define	ZONENAME_ANY		((char *)2)	/* Any jail, not the host. */

struct bsm_record_data {
	u_int64_t	 br_status;	/* Event exit status */
	int		 br_event;	/* Numeric event ID */
	u_int		 br_auid;	/* Record audit ID */
	u_int		 br_euid;	/* Record EUID */
	u_int		 br_egid;	/* Record EGID */
	u_int		 br_ruid;	/* Record RUID */
	u_int		 br_rgid;	/* Record RGID */
	char		*br_path;	/* Record pathname token */
	u_int		 br_sec;	/* Seconds since UNIX epoch */
	u_int		 br_usec;	/* Milli-second resolution */
	u_char		*br_raw;	/* Raw record data */
	int		 br_raw_len;	/* Raw record length */
	int		 br_pid;	/* Process ID */
	int		 br_sid;	/* Session ID */
	dev_t		 br_dev;	/* For fs objects, the device id. */
	ino_t		 br_inode;	/* For fs objects, the inode. */
	const char	*br_zonename;	/* Zone name */
};

#endif	/* DEUCE_H_ */
