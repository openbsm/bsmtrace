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

b_head_t s_parent, s_dynamic;

static int
bsm_match_event(struct bsm_state *bm, struct bsm_record_data *bd)
{
	struct au_event_ent *aue;
	int i, match, evdata;
	struct array *a;

	switch (bm->bm_event_type) {
	case SET_TYPE_AUCLASS:
		/*
		 * XXXCSJP: Could this get quite expensive under high loads if
		 * not cached?
		 */
		aue = getauevnum(bd->br_event);
		if (aue == NULL) {
			bsmtrace_warn("invalid event type: %d",
			    bd->br_event);
			return (0);
		}
		evdata = aue->ae_class;
		break;
	case SET_TYPE_AUEVENT:
		evdata = bd->br_event;
		break;
	default:
		assert(0);
	}
	assert(bm->bm_event_type == SET_TYPE_AUCLASS ||
	    bm->bm_event_type == SET_TYPE_AUEVENT);
	a = &bm->bm_auditevent;
	match = 0;
	for (i = 0; i < a->a_cnt; i++) {
		switch (bm->bm_event_type) {
		case SET_TYPE_AUCLASS:
			if ((evdata & a->a_data[i].value) != 0)
				match = 1;
			break;
		case SET_TYPE_AUEVENT:
		if (a->a_data[i].value == evdata)
			match = 1;
		}
	}
	if ((bm->bm_event_flags & BSM_STATE_EVENT_ANY) != 0)
		match = 1;
	if (a->a_negated != 0)
		match = !match;
	if (!match)
		return (0);
	switch (bm->bm_status) {
	case EVENT_SUCCESS_OR_FAILURE:
		match = 1;
		break;
	case EVENT_SUCCESS:
		match = (bd->br_status == 0);
		break;
	case EVENT_FAILURE:
		match = (bd->br_status != 0);
		break;
	default:
		assert(0);
	}
	return (match);
}

static int
bsm_match_object(struct bsm_state *bm, struct bsm_record_data *bd)
{
	int i, slen, match;
	struct array *ap;
#ifdef PCRE
	int rc;
#endif

	/*
	 * XXXCSJP 
	 *
	 * It is possible for various file events to NOT audit the pathname 
	 * because they are operating on file descriptors.  As a direct result
	 * our event specification could have specified a generic file event
	 * class like "fr" and "fw" which includes events like ftruncate(2)
	 * which does not audit the pathname:
	 *
	 * header,108,10,ftruncate(2),0,Sat Apr 14 19:15:11 2007, + 966 msec
	 * argument,1,0x3,fd
	 * attribute,644,test,test,80,8078349,32267048
	 * subject,test,test,test,test,test,4810,4805,56278,207.161.19.21
	 * return,success,0
	 * trailer,108
	 *
	 * The question becomes, since we can not prove that there was a write
	 * on the object we are interested in, but a write on some anonymous
	 * object has occured, should we still raise an alert?
	 */

	/*
	 * Check to see if the user has supplied any objects. If not, then this
	 * is a member match.
	 */
	ap = &bm->bm_objects;
	if (ap->a_cnt == 0)
		return (1);
	/*
	 * For BSM records which reference a file but do not contain a path
	 * (i.e. fstat(2), fchmod(2) et al), scan the pathname cache for it's
	 * device and see if we can pullup the pathname.
	 */
	if (bd->br_dev != 0 && bd->br_inode != 0 && bd->br_path == NULL)
		bd->br_path = fcache_search(bd->br_dev, bd->br_inode);
	/*
	 * We are interested in particular objects, but the audit record has
	 * not supplied any.  We will treat this as a fail to match.
	 */
	if (bd->br_path == NULL)
		return (0);
	/*
	 * Otherwise, the record contains a pathname which may be represented as
	 * a static string, or as a pcre.
	 */
	if (ap->a_type == STRING_ARRAY) {
		for (match = 0, i = 0; i < ap->a_cnt; i++) {
			slen = strlen(ap->a_data[i].string);
			if (strncmp(ap->a_data[i].string, bd->br_path, slen)
			    == 0) {
				match = 1;
				break;
			}
		}
#ifdef PCRE
	} else if (ap->a_type == PCRE_ARRAY) {
		slen = strlen(bd->br_path);
		for (match = 0, i = 0; i < ap->a_cnt; i++) {
			rc = pcre_exec(ap->a_data[i].pcre, NULL, bd->br_path,
			    slen, 0, 0, NULL, 0);
			if (rc == 0) {
				match = 1;
				break;
			} else if (rc < -1) {
				bsmtrace_fatal("pcre exec failed for pattern"
				    " %s on path %s", ap->a_data[i].pcre,
				    bd->br_path);
			}
		}
#endif
	} else
		/* No other type makes sense. */
		assert(0);
	/* Handle negation. */
	if (ap->a_negated != 0)
		match = !match;
	return (match);
}

static void
bsm_log_sequence(struct bsm_sequence *bs, struct bsm_record_data *bd)
{
	/*
	 * If no logging configuration was specified and we are running
	 * in the foreground, than simply log to stderr.
	 */
	if (opts.Fflag != 0 && opts.lflag == NULL) {
		log_bsm_stderr(bs, bd);
		return;
	}
	if (opts.lflag == NULL)
		return;
	(void) log_bsm_txt_file(bs, bd);
	if (opts.Bflag != 0)
		(void) log_bsm_file(bs, bd);
	/*
	 * If the user specified the -b flag, dump the last BSM record which
	 * resulted in the sequence match to stdout.
	 */
	if (opts.bflag != 0)
		(void) write(1, bd->br_raw, bd->br_raw_len);
}

static inline bool
bsm_dyn_subj_check(struct bsm_sequence *bs_dyn, struct bsm_record_data *bd,
    u_int subj)
{

	/* If the subject doesn't match, we can trivially reject it. */
	if (bs_dyn->bs_subj.bs_dyn_subj != subj)
		return (false);

	/*
	 * If the zonename is NULL, then this is a globally applicable rule.
	 * This and the above case are the two most likely commonly hit, so
	 * we've organized these two first.
	 */
	if (bs_dyn->bs_zonename == NULL)
		return (true);

	/*
	 * Next check for the special case of bs_zonename == NONE, where we can
	 * proceed only if the record's zonename isn't set.  In all remaining
	 * cases, we must have a record zonename.
	 */
	if (bs_dyn->bs_zonename == ZONENAME_NONE)
		return (bd->br_zonename == NULL);
	else if (bd->br_zonename == NULL)
		return (false);

	/* Finally, match on the zonename. */
	return (strcmp(bs_dyn->bs_zonename, bd->br_zonename) == 0);
}

static int
bsm_state_match(struct bsm_sequence *bs, struct bsm_record_data *bd)
{
	struct bsm_state *bm;
	int match;

	assert((bs->bs_seq_flags & BSM_SEQUENCE_DYNAMIC) != 0);
	bm = bs->bs_cur_state;
	/*
	 * Do we have a subject match? At this point we EXPLICITLY do not handle
	 * negation as it should have been handled by the parent.
	 */
	match = bsm_dyn_subj_check(bs, bd, bsm_get_subj(bs, bd));
	if (match == 0)
		return (0);
	/* Match event. */
	match = bsm_match_event(bm, bd);
	if (match == 0)
		return (0);
	/* Match object. */
	match = bsm_match_object(bm, bd);
	return (match);
}

static int
bsm_check_subj_array(u_int subj, struct array *ap)
{
	int match, i;

	for (match = 0, i = 0; i < ap->a_cnt; i++)
		if (ap->a_data[i].value == subj)
			match = 1;
	if (ap->a_negated != 0)
		match = !match;
	return (match);
}

int
bsm_get_subj(struct bsm_sequence *bs, struct bsm_record_data *bd)
{
	u_int subj;

	switch (bs->bs_subj_type) {
	case SET_TYPE_AUID:
		subj = bd->br_auid;
		break;
	case SET_TYPE_RUID:
		subj = bd->br_ruid;
		break;
	case SET_TYPE_EUID:
		subj = bd->br_euid;
		break;
	case SET_TYPE_RGID:
		subj = bd->br_rgid;
		break;
	case SET_TYPE_EGID:
		subj = bd->br_egid;
		break;
	default:
		bsmtrace_fatal("invalid subject type %d", bs->bs_subj_type);
		break;	/* NOTREACHED */
	}
	return (subj);
}

static int
bsm_check_sequence_zone(struct bsm_sequence *bs, struct bsm_record_data *bd)
{

	if (bs->bs_zonename == NULL)
		return (1);

	/*
	 * Match zone as needed.  A NULL bs_zonename means that this sequence is
	 * globally applicable.  If it's not NULL, it may be one of:
	 * - NONE   (Host-only sequence)
	 * - ANY    (Any zone sequence)
	 * - A glob (Zones matching the glob)
	 *
	 * If it's a glob, it will never match the host.  One could also specify a
	 * a glob like '*' to mean ANY, but the latter provides a decent shortcut
	 * that doesn't require the overhead of a glob.
	 */
	if (bs->bs_zonename == ZONENAME_NONE) {
		/* Matches host events only. */
		if (bd->br_zonename != NULL)
			return (0);
		return (1);
	} else if (bd->br_zonename == NULL) {
		/* Either ANY or a glob; cannot match host events. */
		return (0);
	} else if (bs->bs_zonename != ZONENAME_ANY) {
		return (fnmatch(bs->bs_zonename, bd->br_zonename,
		    FNM_PATHNAME) == 0 ? 1 : 0);
	}

	/* bs_zonename == ZONENAME_ANY */
	return (1);
}

static int
bsm_check_parent_sequence(struct bsm_sequence *bs, struct bsm_record_data *bd)
{
	struct bsm_state *bm;
	u_int subj, match;

	assert((bs->bs_seq_flags & BSM_SEQUENCE_PARENT) != 0);
	match = bsm_check_sequence_zone(bs, bd);
	if (match == 0)
		return (0);
	subj = bsm_get_subj(bs, bd);
	match = bsm_check_subj_array(subj, &bs->bs_subj.bs_par_subj);
	if (match == 0 && (bs->bs_seq_flags & BSM_SEQUENCE_SUBJ_ANY) == 0)
		return (0);
	assert(bs->bs_cur_state == NULL && !TAILQ_EMPTY(&bs->bs_mhead));
	bm = TAILQ_FIRST(&bs->bs_mhead);
	/* Match event. */
	match = bsm_match_event(bm, bd);
	if (match == 0)
		return (0);
	/* Match object. */
	match = bsm_match_object(bm, bd);
	return (match);
}

static struct bsm_sequence *
bsm_dyn_sequence_find(struct bsm_sequence *bs, struct bsm_record_data *bd,
    u_int subj)
{
	struct bsm_sequence *bs_dyn;

	assert((bs->bs_seq_flags & BSM_SEQUENCE_PARENT) != 0);
	TAILQ_FOREACH(bs_dyn, &s_dynamic, bs_glue)
		if (bs_dyn->bs_par_sequence == bs &&
		    bs_dyn->bs_subj_type == bs->bs_subj_type &&
		    bsm_dyn_subj_check(bs_dyn, bd, subj))
			return (bs_dyn);
	return (NULL);
}

static void
bsm_free_raw_data(struct bsm_sequence *bs)
{
	struct bsm_state *bm;

	TAILQ_FOREACH(bm, &bs->bs_mhead, bm_glue) {
		if (bm->bm_raw != NULL)
			free(bm->bm_raw);
		bm->bm_raw_len = 0;
	}
}

static void
bsm_copy_states(struct bsm_sequence *bs_old, struct bsm_sequence *bs_new)
{
	struct bsm_state *bm, *bm2;

	/*
	 * Make sure that we initialize the new tailq head to NULL
	 * otherwise we would be recursively adding states.
	 */
	debug_printf("%s: copying states from sequence %p\n", __func__, bs_old);
	TAILQ_INIT(&bs_new->bs_mhead);
	TAILQ_FOREACH(bm, &bs_old->bs_mhead, bm_glue) {
		bm2 = calloc(1, sizeof(*bm2));
		if (bm2 == NULL) {
			bsmtrace_fatal("%s: calloc failed", __func__);
		}
		*bm2 = *bm;
		TAILQ_INSERT_TAIL(&bs_new->bs_mhead, bm2, bm_glue);
	}
}

static caddr_t
bsm_copy_record_data(struct bsm_record_data *bd)
{
	caddr_t record;

	assert(bd != NULL);
	record = malloc(bd->br_raw_len);
	if (record == NULL)
		bsmtrace_fatal("malloc failed");
	bcopy(bd->br_raw, record, bd->br_raw_len);
	return (record);
}

static void
bsm_free_sequence(struct bsm_sequence *bs)
{
	struct bsm_state *bm;

	assert(bs != NULL);
	debug_printf("%s: freeing sequence %p\n", __func__, bs);
	assert((bs->bs_seq_flags & BSM_SEQUENCE_DYNAMIC) != 0);
	if (bs->bs_zonename != NULL && bs->bs_zonename != ZONENAME_NONE) {
		/*
		 * Having matched any zone should have triggered a copy of the
		 * name.
		 */
		assert(bs->bs_zonename != ZONENAME_ANY);
		free(bs->bs_zonename);
	}
	bsm_free_raw_data(bs);
	while (!TAILQ_EMPTY(&bs->bs_mhead)) {
		bm = TAILQ_FIRST(&bs->bs_mhead);
		TAILQ_REMOVE(&bs->bs_mhead, bm, bm_glue);
		free(bm);
	}
	free(bs);
#ifdef INVARIANTS
	bs = 0xdeadc0de;
#endif
}

/*
 * Implement a function which produces random values with an interesting
 * property.  This function will produce a random value, where the probability
 * of this value being between 0 and size is specified by prob.
 *
 * Let v be > 0 and < 1 (random value)
 * Let P (probability) be > 0 and < 1
 *
 * Rv = v * (range / P); 
 *
 */
static float
bsm_rand_bias(float size, float prob)
{
	unsigned int val;
	float r;

	val = arc4random();
	r = (float)val;
	while (r > 1)
		r = r / 10;
	return (r * (size / prob));
}

static struct bsm_sequence *
bsm_sequence_clone(struct bsm_sequence *bs, u_int subj,
    struct bsm_record_data *bd)
{
	struct bsm_sequence *bs_new;
	struct bsm_state *bm;
	float size, prob;
	int rnd;

	bs_new = bsm_dyn_sequence_find(bs, bd, subj);
	if (bs_new != NULL) {
		if ((bs_new->bs_seq_flags & BSM_SEQUENCE_DESTROY) != 0) {
			TAILQ_REMOVE(&s_dynamic, bs_new, bs_glue);
			bsm_free_sequence(bs_new);
		}
		return (NULL);
	}
	bs_new = calloc(1, sizeof(*bs_new));
	if (bs_new == NULL) {
		bsmtrace_warn("%s: calloc failed", __func__);
		return (NULL);
	}
	debug_printf("%u:%s: sequence %p cloned and linked\n",
	    time(NULL), bs->bs_label, bs_new);
	*bs_new = *bs;
	/*
	 * The BSM sequence flags are mutually exclusive.
	 */
	bs_new->bs_seq_flags &= ~BSM_SEQUENCE_PARENT;
	bs_new->bs_seq_flags |= BSM_SEQUENCE_DYNAMIC;
	bs_new->bs_subj.bs_dyn_subj = subj;
	bs_new->bs_par_sequence = bs;
	bs_new->bs_first_match = bd->br_sec;
	bs_new->bs_mtime = bd->br_sec;
	/*
	 * We need to copy the applicable zone to bs_new if it should actually
	 * be used.  Effectively, we'll either copy the zonename that first
	 * matched or we'll have copied over ZONENAME_NONE to indicate that
	 * particular constraint.
	 */
	if (bs->bs_zonename != NULL && bs->bs_zonename != ZONENAME_NONE) {
		/*
		 * If we matched a glob/any, then this should be trivially true.
		 */
		assert(bd->br_zonename != NULL);
		bs_new->bs_zonename = strdup(bd->br_zonename);
	}

	bsm_copy_states(bs, bs_new);
	/*
	 * If we have made it this far, we can assume that we have more than
	 * one finite state defined.
	 */
	assert(TAILQ_FIRST(&bs->bs_mhead) != TAILQ_LAST(&bs->bs_mhead, tailq));
	bm = TAILQ_FIRST(&bs_new->bs_mhead);
	assert(bm != NULL);
	bm->bm_raw = bsm_copy_record_data(bd);
	bm->bm_raw_len = bd->br_raw_len;
	bs_new->bs_cur_state = TAILQ_NEXT(bm, bm_glue);
	/*
	 * Handle the randomization of the timeout window here.
	 */
	if (bs_new->bs_seq_time_wnd != 0) {
		size = bs_new->bs_seq_time_wnd;
		if (bs_new->bs_seq_time_wnd_prob > 0)
			prob = (float)bs_new->bs_seq_time_wnd_prob / 100;
		else
			prob = (float)(65 / 100);
		rnd = bsm_rand_bias(size, prob);
		bs_new->bs_timeout = bs_new->bs_timeout + rnd;
	}
	return (bs_new);
}

static void
bsm_sequence_scan(struct bsm_record_data *bd)
{
	struct bsm_sequence *bs, *bs_dyn, *bs_temp;
	struct bsm_state *bm;
	u_int match, subj;

	/* Match dynamic sequences. */
	TAILQ_FOREACH_SAFE(bs, &s_dynamic, bs_glue, bs_temp) {
		assert((bs->bs_seq_flags & BSM_SEQUENCE_DYNAMIC) != 0);
		/*
		 * Make sure that every sequence here has multiple states.
		 */
		assert(TAILQ_LAST(&bs->bs_mhead, tailq) !=
		    TAILQ_FIRST(&bs->bs_mhead));
		/*
		 * If the sequence was marked for destruction and it didn't
		 * match any parent sequences, destroy it here. The only
		 * reason we do not destroy is we do not want the parent
		 * matching on it.
		 */
		if ((bs->bs_seq_flags & BSM_SEQUENCE_DESTROY) != 0) {
			TAILQ_REMOVE(&s_dynamic, bs, bs_glue);
			bsm_free_sequence(bs);
			continue;
		}
		if (bs->bs_timeout > 0 &&
		    (bd->br_sec - bs->bs_mtime) > bs->bs_timeout) {
			TAILQ_REMOVE(&s_dynamic, bs, bs_glue);
			bsm_free_sequence(bs);
			continue;
		}
		match = bsm_state_match(bs, bd);
		if (match == 0)
			continue;
		bm = bs->bs_cur_state;
		bsm_run_trigger(bd, bm);
		if (opts.bflag)
			(void) write(1, bd->br_raw, bd->br_raw_len);
		bm->bm_raw = bsm_copy_record_data(bd);
		bm->bm_raw_len = bd->br_raw_len;
		/* Final state (complete sequence) has been matched. */
		if (bm == TAILQ_LAST(&bs->bs_mhead, tailq)) {
			assert((bs->bs_seq_flags & BSM_SEQUENCE_DESTROY) == 0);
			bsm_log_sequence(bs, bd);
			bs->bs_seq_flags |= BSM_SEQUENCE_DESTROY;
			continue;
		}
		debug_printf("%s: state transition cur=%p\n", bs->bs_label,
		    TAILQ_NEXT(bm, bm_glue));
		bs->bs_cur_state = TAILQ_NEXT(bm, bm_glue);
	}
	/* Match parent sequences. */
	TAILQ_FOREACH(bs, &s_parent, bs_glue) {
		assert((bs->bs_seq_flags & BSM_SEQUENCE_PARENT) != 0);
		match = bsm_check_parent_sequence(bs, bd);
		if (match == 0)
			continue;
		bsm_run_trigger(bd, TAILQ_FIRST(&bs->bs_mhead));
		if (opts.bflag)
			(void) write(1, bd->br_raw, bd->br_raw_len);
		/*
		 * It's possible that the parent sequence has only one state
		 * defined, in which case, raise an alert and don't bother
		 * creating a dynamic object for it.
		 */
		if (TAILQ_FIRST(&bs->bs_mhead) ==
		    TAILQ_LAST(&bs->bs_mhead, tailq)) {
			bsm_log_sequence(bs, bd);
			continue;
		}
		debug_printf("%d:%s: state transition\n", time(NULL), bs->bs_label);
		subj = bsm_get_subj(bs, bd);
		bs_dyn = bsm_sequence_clone(bs, subj, bd);
		if (bs_dyn == NULL)
			continue;
		TAILQ_INSERT_HEAD(&s_dynamic, bs_dyn, bs_glue);
	}
}

void
bsm_loop(char *atrail)
{
	struct bsm_record_data bd;
	int reclen, bytesread, recsread;
	u_char *bsm_rec;
	tokenstr_t tok;
	FILE *fp;

	if (strcmp(opts.aflag, "-") == 0)
		fp = stdin;
	else
		fp = fopen(opts.aflag, "r");
	if (fp == NULL)
		bsmtrace_fatal("%s: %s", opts.aflag, strerror(errno));
	if (strcmp(opts.aflag, DEFAULT_AUDIT_TRAIL) == 0)
		audit_pipe_fd = fileno(fp);
	debug_printf("opened '%s' for audit monitoring\n", opts.aflag);
	/*
	 * Process the BSM record, one token at a time.
	 */
	recsread = 0;
	while ((reclen = au_read_rec(fp, &bsm_rec)) != -1) {
		/*
		 * If we are reading data from the audit pipe, we need check
		 * how many records, if any have been dropped by the kernel.
		 * If any record loss has been identified, pipe_analyze_loss()
		 * should increase the internal audit pipe queue length.
		 */
		if (audit_pipe_fd > 0 && (recsread % 50) == 0)
			pipe_analyze_loss(audit_pipe_fd);
		bzero(&bd, sizeof(bd));
		bd.br_raw = bsm_rec;
		bd.br_raw_len = reclen;
		bytesread = 0;
		/*
		 * Iterate through each BSM token, extracting the bits that are
		 * required to starting processing sequences.
		 */
		while (bytesread < reclen) {
			if (au_fetch_tok(&tok, bsm_rec + bytesread,
			    reclen - bytesread) < 0) {
				bsmtrace_warn("incomplete record");
				break;
			}
			switch (tok.id) {
			case AUT_HEADER32:
				bd.br_event = tok.tt.hdr32.e_type;
				bd.br_sec = tok.tt.hdr32.s;
				bd.br_usec = tok.tt.hdr32.ms;
				break;
			case AUT_HEADER32_EX:
				bd.br_event = tok.tt.hdr32_ex.e_type;
				bd.br_sec = tok.tt.hdr32_ex.s;
				bd.br_usec = tok.tt.hdr32_ex.ms;
				break;
			case AUT_HEADER64:
				bd.br_event = tok.tt.hdr64.e_type;
				bd.br_sec = tok.tt.hdr64.s;
				bd.br_usec = tok.tt.hdr64.ms;
				break;
			case AUT_HEADER64_EX:
				bd.br_event = tok.tt.hdr64_ex.e_type;
				bd.br_sec = tok.tt.hdr64_ex.s;
				bd.br_usec = tok.tt.hdr64_ex.ms;
				break;
			case AUT_SUBJECT32:
				bd.br_auid = tok.tt.subj32.auid;
				bd.br_euid = tok.tt.subj32.euid;
				bd.br_egid = tok.tt.subj32.egid;
				bd.br_ruid = tok.tt.subj32.ruid;
				bd.br_rgid = tok.tt.subj32.rgid;
				bd.br_pid = tok.tt.subj32.pid;
				bd.br_sid = tok.tt.subj32.sid;
				break;
			case AUT_SUBJECT64:
				bd.br_auid = tok.tt.subj64.auid;
				bd.br_euid = tok.tt.subj64.euid;
				bd.br_egid = tok.tt.subj64.egid;
				bd.br_ruid = tok.tt.subj64.ruid;
				bd.br_rgid = tok.tt.subj64.rgid;
				bd.br_pid = tok.tt.subj64.pid;
				bd.br_sid = tok.tt.subj64.sid;
				break;
			case AUT_SUBJECT32_EX:
				bd.br_auid = tok.tt.subj32_ex.auid;
				bd.br_euid = tok.tt.subj32_ex.euid;
				bd.br_egid = tok.tt.subj32_ex.egid;
				bd.br_ruid = tok.tt.subj32_ex.ruid;
				bd.br_rgid = tok.tt.subj32_ex.rgid;
				bd.br_pid = tok.tt.subj32.pid;
				bd.br_sid = tok.tt.subj32.sid;
				break;
			case AUT_RETURN32:
				bd.br_status = (u_int64_t)tok.tt.ret32.status;
				break;
			case AUT_RETURN64:
				bd.br_status = tok.tt.ret64.err;
				break;
			case AUT_ATTR:
			case AUT_ATTR32:
				bd.br_dev = tok.tt.attr32.fsid;
				bd.br_inode = tok.tt.attr32.nid;
				break;
			case AUT_PATH:
				bd.br_path = tok.tt.path.path;
				break;
			case AUT_ZONENAME:
				bd.br_zonename = tok.tt.zonename.zonename;
				break;
			}
			bytesread += tok.len;
		}
		if (bd.br_path != NULL && bd.br_dev != 0 && bd.br_inode != 0)
			fcache_add_entry(bd.br_dev, bd.br_inode, bd.br_path);
		bsm_sequence_scan(&bd);
		free(bsm_rec);
		recsread++;
	}
	(void) fclose(fp);
}
