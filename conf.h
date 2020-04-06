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
#ifndef BSM_CONF_H_
#define	BSM_CONF_H_

extern bsm_set_head_t	bsm_set_head;
extern int 		lineno;
extern const char	*yyfile;
extern int		logfilefd;

struct bsm_set		*conf_get_bsm_set(char *);
struct bsm_sequence	*conf_get_parent_sequence(char *);
void			 conf_merge_bsm_set(struct array *desta, struct bsm_set *src);
void			 conf_load(char *);
void			 conf_detail(int, const char *, ...) __attribute__ ((noreturn));
void			 conf_handle_multiplier(struct bsm_sequence *,
			     struct bsm_state *);
void			 conf_array_add(const char *, struct array *, int);
void			 conf_sequence_set_subj(struct bsm_sequence *,
			     struct bsm_set *, int);
int			 conf_set_type(char *);
const char		*conf_get_file(void);
void			 yyerror(const char *);
int			 yywrap(void);
void			 conf_set_log_channel(struct bsm_set *,
			     struct bsm_sequence *);
int			 conf_return_scope(char *);
#endif	/* BSM_CONF_H_ */
