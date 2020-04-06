%{
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

extern int	yylex(void);
extern int	include(const char *);

static struct bsm_sequence	*bs_state;	/* BSM sequence state */
static struct bsm_set		*set_state;	/* BSM set state */
static struct bsm_state	*bm_state;	/* BSM state */
static struct array		 array_state;	/* Volatile array */
%}

%union {
	u_int32_t		 num;
	char			*str;
	struct array		*array;
	struct bsm_set		*bsm_set;
	struct bsm_state	*bsm_state;
}

%token	DEFINE SET OBJECT SEQUENCE STATE EVENT TRIGGER
%token	STATUS MULTIPLIER OBRACE EBRACE SEMICOLON COMMA SUBJECT
%token	STRING ANY SUCCESS FAILURE INTEGER TIMEOUT NOT HOURS MINUTES DAYS
%token	PRIORITY WEEKS SECONDS NONE QUOTE OPBRACKET EPBRACKET LOGCHAN LOGFILE
%token	DIRECTORY LOG SCOPE SERIAL TIMEOUTWND TIMEOUTPROB CONFIG INCLUDE ZONE
%type	<num> status_spec SUCCESS FAILURE INTEGER multiplier_spec timeout_spec
%type	<num> serial_spec negate_spec priority_spec scope_spec timeout_wnd_spec
%type	<num> timeout_prob_spec time_spec
%type	<str> STRING zone_spec
%type	<array> set_list set_list_ent
%type	<bsm_set> anon_set
%type	<bsm_state> state

%%

root	: /* empty */
	| root cmd
	;

cmd	:
	define_def
	| sequence_def
	| INCLUDE STRING SEMICOLON {
		include($2);
	}
	| logfile_def
	;

define_def:
	DEFINE SET STRING OPBRACKET STRING EPBRACKET
	{
		assert(set_state == NULL);
		if ((set_state = calloc(1, sizeof(*set_state))) == NULL)
			bsmtrace_fatal("%s: calloc failed", __func__);
		if ((set_state->bss_type = conf_set_type($5)) == -1)
			conf_detail(0, "%s: invalid set type", $5);
		/* free() this later. */
		set_state->bss_name = $3;
		set_state->bss_file = yyfile;
	}
	OBRACE set_list SEMICOLON EBRACE SEMICOLON
	{
		struct array *src, *dst;

		src = $9;
		dst = &set_state->bss_data;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		/*
		 * Insert to the head so that the latest set is always found
		 * first.
		 */
		TAILQ_INSERT_HEAD(&bsm_set_head, set_state, bss_glue);
		set_state = NULL;
	}
	;

negate_spec: /* Empty */
	{
		$$ = 0;
	}
	| NOT
	{
		$$ = 1;
	}
	;

anon_set:
	OPBRACKET STRING EPBRACKET OBRACE
	{
		struct bsm_set *new;

		if ((new = calloc(1, sizeof(*new))) == NULL)
			bsmtrace_fatal("%s: calloc failed", __func__);
		if ((new->bss_type = conf_set_type($2)) == -1)
			conf_detail(0, "%s: invalid set type", $2);
		set_state = new;
	}
	set_list SEMICOLON EBRACE
	{
		struct array *src, *dst;

		assert(set_state->bss_type != 0);
		src = $6;
		dst = &set_state->bss_data;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		$$ = set_state;
		set_state = NULL;
	}
	;

subject_spec:
	SUBJECT ANY SEMICOLON
	{
		bs_state->bs_seq_flags |= BSM_SEQUENCE_SUBJ_ANY;
		bs_state->bs_subj_type = SET_TYPE_AUID;
	}
	| SUBJECT negate_spec STRING SEMICOLON
	{
		struct bsm_set *sptr;

		if ((sptr = conf_get_bsm_set($3)) == NULL)
			conf_detail(0, "%s: invalid set", $3);
		conf_sequence_set_subj(bs_state, sptr, $2);
	}
	| SUBJECT negate_spec anon_set SEMICOLON
	{
		assert($3->bss_type != 0);
		conf_sequence_set_subj(bs_state, $3, $2);
	}
	;

timeout_prob_spec:
	TIMEOUTPROB INTEGER SEMICOLON
	{
		$$ = $2;
	}
	;

timeout_wnd_spec:
	TIMEOUTWND time_spec SEMICOLON
	{
		$$ = $2;
	}
	;

time_spec:
	INTEGER SECONDS
	{
		$$ = $1;
	}
	| INTEGER HOURS
	{
		$$ = $1 * 3600;
	}
	| INTEGER MINUTES
	{
		$$ = $1 * 60;
	}
	| INTEGER DAYS
	{
		$$ = $1 * 3600 * 24;
	}
	| INTEGER WEEKS
	{
		$$ = $1 * 3600 * 24 * 7;
	}
	| NONE
	{
		$$ = 0;
	}
	;

logfile_def:
	LOGFILE STRING SEMICOLON
	{
		int fd;

		if ((fd = log_get_logfile($2)) < 0)
			conf_detail(0, "%s: invalid logfile", $2);
		logfilefd = fd;
		free($2);
	}
	;

timeout_spec:
	TIMEOUT time_spec SEMICOLON
	{
		$$ = $2;
	}
	;

sequence_def:
	SEQUENCE
	{
		assert(bs_state == NULL);
		if ((bs_state = calloc(1, sizeof(*bs_state))) == NULL)
			bsmtrace_fatal("%s: calloc failed", __func__);
		/*
		 * This will be a parent sequence.  It should use whatever the global
		 * logfile is set to at definition time.
		 */
		bs_state->bs_logfile = logfilefd;
		bs_state->bs_seq_flags |= BSM_SEQUENCE_PARENT;
		bs_state->bs_seq_scope = BSM_SCOPE_GLOBAL;
                bs_state->bs_subj_type = SET_TYPE_NOOP;
		TAILQ_INIT(&bs_state->bs_mhead);
	}
	STRING OBRACE sequence_options EBRACE SEMICOLON
	{
                /* Check for valid subject specified in sequence options. */
                if (bs_state->bs_subj_type == SET_TYPE_NOOP)
                        conf_detail(0, "%s: must specify a subject", $3);
		if (conf_get_parent_sequence($3) != NULL)
			conf_detail(0, "%s: sequence exists", $3);
		if ((bs_state->bs_label = strdup($3)) == NULL)
			bsmtrace_fatal("%s: strdup failed", __func__);
		TAILQ_INSERT_HEAD(&s_parent, bs_state, bs_glue);
		bs_state = NULL;
	}
	;

priority_spec:
	PRIORITY INTEGER SEMICOLON
	{
		$$ = $2;
	}
	;

zone_spec:
	ZONE NONE SEMICOLON
	{
		$$ = ZONENAME_NONE;
	}
	| ZONE ANY SEMICOLON
	{
		$$ = ZONENAME_ANY;
	}
	| ZONE STRING SEMICOLON
	{
		$$ = $2;
	}
	;

scope_spec:
	SCOPE STRING SEMICOLON
	{
		int scope;

		scope = conf_return_scope($2);
		if (scope < 0)
			conf_detail(0, "%s: invalid scope", $2);
		bs_state->bs_seq_scope = scope;
	}
	;

serial_spec:
	SERIAL INTEGER SEMICOLON
	{
		$$ = $2;
	}
	;

sequence_options: /* Empty */
	| sequence_options subject_spec
	{
		assert(bs_state != NULL);
	}
	| sequence_options zone_spec
	{
		assert(bs_state != NULL);
		if ($2 == ZONENAME_NONE || $2 == ZONENAME_ANY)
			bs_state->bs_zonename = $2;
		else if ((bs_state->bs_zonename = strdup($2)) == NULL)
			bsmtrace_fatal("%s: strdup failed", __func__);
	}
	| sequence_options timeout_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_timeout = $2;
	}
	| sequence_options state
	{
		assert(bs_state != NULL);
		conf_handle_multiplier(bs_state, $2);
	}
	| sequence_options priority_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_priority = $2;
	}
	| sequence_options scope_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_seq_flags |= $2;
	}
	| sequence_options serial_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_seq_serial = $2;
	}
	| sequence_options timeout_wnd_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_seq_time_wnd = $2;
	}
	| sequence_options timeout_prob_spec
	{
		assert(bs_state != NULL);
		bs_state->bs_seq_time_wnd_prob = $2;
	}
	;

type_spec:
	EVENT negate_spec STRING SEMICOLON
	{
		struct array *src, *dst;
		struct bsm_set *ptr;

		if ((ptr = conf_get_bsm_set($3)) == NULL)
			conf_detail(0, "%s: invalid set", $3);
		if (ptr->bss_type != SET_TYPE_AUCLASS &&
		    ptr->bss_type != SET_TYPE_AUEVENT)
			conf_detail(0, "supplied set contains no audit "
			    "events or classes");
		bm_state->bm_event_type = ptr->bss_type;
		src = &ptr->bss_data;
		dst = &bm_state->bm_auditevent;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		dst->a_negated = $2;
	}
	| EVENT negate_spec anon_set SEMICOLON
	{
		struct array *src, *dst;

		if ($3->bss_type != SET_TYPE_AUCLASS &&
		    $3->bss_type != SET_TYPE_AUEVENT)
			conf_detail(0, "supplied set contains no audit "
			    "events or classes");
		bm_state->bm_event_type = $3->bss_type;
		src = &$3->bss_data;
		dst = &bm_state->bm_auditevent;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		dst->a_negated = $2;
	}
	| EVENT ANY SEMICOLON
	{
		bm_state->bm_event_type = SET_TYPE_AUEVENT;
		bm_state->bm_event_flags |= BSM_STATE_EVENT_ANY;
		free(array_state.a_data);
		bzero(&array_state, sizeof(struct array));
	}
	;

object_spec:
	OBJECT negate_spec STRING SEMICOLON
	{
		struct array *src, *dst;
		struct bsm_set *ptr;

		if ((ptr = conf_get_bsm_set($3)) == NULL)
			conf_detail(0, "%s: invalid set", $3);
#ifdef PCRE
		if (ptr->bss_type != SET_TYPE_PATH &&
		    ptr->bss_type != SET_TYPE_PCRE)
			conf_detail(0, "objects must be of type path or pcre");
#else
		if (ptr->bss_type != SET_TYPE_PATH)
			conf_detail(0, "objects must be of type path");
#endif
		src = &ptr->bss_data;
		dst = &bm_state->bm_objects;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		dst->a_negated = $2;
	}
	| OBJECT negate_spec anon_set SEMICOLON
	{
		struct array *src, *dst;

		src = &$3->bss_data;
#ifdef PCRE
		if ($3->bss_type != SET_TYPE_PATH &&
		    $3->bss_type != SET_TYPE_PCRE)
			conf_detail(0, "objects must be of type path or pcre");
#else
		if ($3->bss_type != SET_TYPE_PATH)
			conf_detail(0, "objects must be of type path");
#endif
		dst = &bm_state->bm_objects;
		*dst = *src;
		bzero(&array_state, sizeof(struct array));
		dst->a_negated = $2;
	}
	;

status_spec:
	STATUS SUCCESS SEMICOLON
	{
		$$ = EVENT_SUCCESS;
	}
	| STATUS FAILURE SEMICOLON
	{
		$$ = EVENT_FAILURE;
	}
	| STATUS ANY SEMICOLON
	{
		$$ = EVENT_SUCCESS_OR_FAILURE;
	}
	;

multiplier_spec:
	MULTIPLIER INTEGER SEMICOLON
	{
		$$ = $2;
	}
	;

trigger_spec:
	TRIGGER STRING SEMICOLON
	{
		strlcpy(bm_state->bm_trig, $2, sizeof(bm_state->bm_trig));
	}
	;

state_options: /* empty */
	| state_options type_spec
	| state_options status_spec
	{
		assert(bm_state != NULL);
		bm_state->bm_status = $2;
	}
	| state_options multiplier_spec
	{
		assert(bm_state != NULL);
		bm_state->bm_multiplier = $2;
	}
	| state_options object_spec
	| state_options trigger_spec
	;

state:
	STATE
	{
		assert(bm_state == NULL);
		if ((bm_state = calloc(1, sizeof(*bm_state))) == NULL)
			bsmtrace_fatal("%s: calloc failed", __func__);
	}
	OBRACE state_options EBRACE SEMICOLON
	{
		$$ = bm_state;
		bm_state = NULL;
	}
	;

set_list:
	set_list_ent
	{
		$$ = &array_state;
	}
	| set_list COMMA set_list_ent
	{
		assert($1 != NULL && $3 != NULL);
		$$ = &array_state;
	}
	;

set_list_ent:
	SET STRING
	{
		struct bsm_set *ptr;
		assert(set_state != NULL && $2 != NULL);

		if ((ptr = conf_get_bsm_set($2)) == NULL)
			conf_detail(0, "%s: invalid set", $2);
		if (set_state->bss_type != ptr->bss_type)
			conf_detail(0, "%s: type mismatch", $2);
		conf_merge_bsm_set(&array_state, ptr);
		free($2);
		$$ = &array_state;
	}
	| STRING
	{
		assert(set_state != NULL && $1 != NULL);
		conf_array_add($1, &array_state, set_state->bss_type);
		free($1);
		$$ = &array_state;
	}
	| INTEGER
	{
		char buf[64];

		(void) sprintf(buf, "%d", $1);
		conf_array_add(strdup(buf), &array_state, set_state->bss_type);
		$$ = &array_state;
	}
	| OPBRACKET STRING EPBRACKET
	{
		assert($2 != NULL);
		conf_array_add($2, &array_state, set_state->bss_type);
		$$ = &array_state;
	}
	;
