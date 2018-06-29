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

static const struct _exptab {
	char	*str;
	int	 val;
} exptab[] = {
	{ "subject",	EXP_USER },
	{ "object",	EXP_OBJECT },
	{ "esubject",	EXP_EUSER },
	{ NULL,		0 }
};

char *
bsm_expand_trigger(struct bsm_record_data *bd, struct bsm_state *bm)
{
	char *p0, *p1, *ret, token[2048], *tptr;
	const struct _exptab *expptr;
	struct passwd *pw;
	size_t allocated;

	/* This is a reasonable starting point. */
	allocated = strlen(bm->bm_trig) + 1024;
	if ((p1 = ret = calloc(1, allocated)) == NULL)
		return (NULL);
	for (p0 = bm->bm_trig; *p0 != '\0';) {
		if (*p0 == '$') {
			/* Look ahead for expansion. */
			tptr = token;
			while (isalpha(*(++p0)))
				*(tptr++) = *p0;
			*tptr = '\0';
			for (expptr = exptab; expptr->str != NULL; expptr++)
				if (strcmp(expptr->str, token) == 0)
					break;
			if (expptr->str == NULL) {
				/* Expansion failed as an invalid variable
				 * identifier was specified.  We should
				 * probably check for this while loading
				 * the configuration file and report on it
				 * at that point. */
				free(ret);
				return (NULL);
			}
			switch (expptr->val) {
			case EXP_USER:
				if ((pw = getpwuid(bd->br_auid)) == NULL)
					(void) strlcpy(token, "non-attributable",
					    sizeof(token));
				else
					(void) strlcpy(token, pw->pw_name,
					    sizeof(token));
				break;
			case EXP_EUSER:
				if ((pw = getpwuid(bd->br_euid)) == NULL)
					(void) strlcpy(token, "non-attributable",
					    sizeof(token));
				else
					(void) strlcpy(token, pw->pw_name,
					    sizeof(token));
				break;
			case EXP_OBJECT:
				if (bd->br_path != NULL)
					(void) strlcpy(token, bd->br_path,
					    sizeof(token));
				else {
					free(ret);
					return (NULL);
				}
				break;
			default:
				assert(0);
			}
			(void) strlcat(ret, token, allocated);
			p1 = ret + strlen(ret);
		} else
			*(p1++) = *(p0++);
		if (p1 >= (ret + allocated)) {
			free(ret);
			return (NULL);
		}
	}
	return (ret);
}

void
bsm_run_trigger(struct bsm_record_data *bd, struct bsm_state *bm)
{
	char *cmd, *ptr;
	char **args;
	int ret, n;

	assert((bd != NULL) && (bm != NULL));
	if (bm->bm_trig[0] == '\0')
		return;
	cmd = bsm_expand_trigger(bd, bm);
	if (cmd != NULL) {
		/*
		 * NB: should the failure to execute a trigger be fatal?
		 */
		ret = fork();
		if (ret < 0)
			bsmtrace_fatal("%s: fork failed", __func__);
		if (ret == 0) {
			n = 0;
			args = calloc(1, sizeof(char *) * TRIGGER_ARGS_MAX);
			if (args == NULL)
				bsmtrace_fatal("%s: calloc failed", __func__);
			debug_printf("executing trigger: '%s'\n", cmd);
			while ((ptr = strsep(&cmd, " ")) != NULL) {
				if (*ptr == '\0')
					continue;
				if ((args[n++] = strdup(ptr)) == NULL)
					bsmtrace_fatal("%s: strdup failed",
					    __func__);
			}
			(void) execve(args[0], args, NULL);
			bsmtrace_fatal("execve: %s", strerror(errno));
		}
		free(cmd);
	} else /*
		* NB: we should Report expansion variables which failed.
		*/
		bsmtrace_warn("%s: expansion failed", bm->bm_trig);
}
