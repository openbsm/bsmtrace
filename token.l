%{
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
#include <limits.h>

#include "includes.h"
#include "y.tab.h"

#define YY_NO_UNPUT

/* Modelled after config(8) on FreeBSD. */
struct incl {
	struct incl	*incl_prev;
	YY_BUFFER_STATE	incl_buf;
	const char	*incl_fname;
	int		 incl_lineno;
	int		 incl_logfilefd;
};

static struct incl	*inclp;

static void endinclude(void);
%}

%option nounput

tokenchar	[^[:blank:];,<>"\n]
tokenstring	{tokenchar}+
integer		[0-9]+

%%
\#.*		/* ignore comments */
any		return (ANY);
days		return (DAYS);
define		return (DEFINE);
directory	return (DIRECTORY);
event		return (EVENT);
failure		return (FAILURE);
hours		return (HOURS);
include		return (INCLUDE);
log		return (LOG);
log-channel	return (LOGCHAN);
logfile		return (LOGFILE);
minutes		return (MINUTES);
multiplier	return (MULTIPLIER);
none		return (NONE);
not		return (NOT);
\!		return (NOT);
object		return (OBJECT);
priority	return (PRIORITY);
scope		return (SCOPE);
seconds		return (SECONDS);
sequence	return (SEQUENCE);
serial		return (SERIAL);
set		return (SET);
state		return (STATE);
status		return (STATUS);
subject		return (SUBJECT);
success		return (SUCCESS);
timeout		return (TIMEOUT);
timeout-window	return (TIMEOUTWND);
timeout-prob	return (TIMEOUTPROB);
trigger		return (TRIGGER);
weeks		return (WEEKS);
zone		return (ZONE);
{integer}	{
			yylval.num = atoi(yytext);
			return (INTEGER);
		}
\n		lineno++;
[ \t]+		/* whitespace ignored */
\{		return (OBRACE);
\}		return (EBRACE);
\<		return (OPBRACKET);
\>		return (EPBRACKET);
\;		return (SEMICOLON);
\,		return (COMMA);
<<EOF>>	{
			if (inclp == NULL)
				return (YY_NULL);
			endinclude();
			/* carry on */
		}
\"		{
			char buf[1024], *ptr;
			char c;
			int escaped = 0;
			int firstq = lineno;

			memset(buf, 0, sizeof(buf));
			for (ptr = buf; strlen(buf) < (sizeof(buf) - 1);
			    ptr++) {
				c = input();
				if (escaped && c != EOF) {
					*ptr = c;
					escaped = 0;
					continue;
				}
				switch (c) {
				case '\\':
					ptr--;
					escaped = 1;
					break;
				case '\n':
					/* newlines encountered within
					 * quoted strings are converted
					 * into a single space. */
					*ptr = ' ';
					lineno++;
					break;
				case '"':	/* end quote */
					ptr = NULL;
					break;
				case EOF:
					conf_detail(firstq, "unmatched \"");
					exit(1);
				default:
					*ptr = c;
					break;
				}
				if (ptr == NULL)
					break;
			}
			yylval.str = strdup(buf);
			assert(yylval.str != NULL);
			return (STRING);
		}
{tokenstring}	{
			yylval.str = strdup(yytext);
			assert(yylval.str != NULL);
			return (STRING);
		}
%%

int
include(const char *fname)
{
	char filepath[PATH_MAX];
	char *tslash;
	FILE *fp;
	struct incl *incl;

	if (fname[0] == '/') {
		if (strlcpy(filepath, fname, sizeof(filepath)) >=
		    sizeof(filepath)) {
			yyerror("invalid include file path");
			return (-1);
		}
	} else {
		/*
		 * Grab it relative to the directory the config file is in.  We
		 * have already opened the config file, so this part at least
		 * won't truncate.
		 */
		(void) strlcpy(filepath, conf_get_file(), sizeof(filepath));
		tslash = strrchr(filepath, '/');

		/*
		 * And we opened it as a file, so a trailing slash won't be the
		 * last character.  If we didn't find a slash, we'll assume
		 * relative to the working directory because the config is in
		 * the working directory.
		 */
		if (tslash != NULL) {
			*(tslash + 1) = '\0';
		} else {
			filepath[0] = '\0';
		}

		if (strlcat(filepath, fname, sizeof(filepath)) >=
		    sizeof(filepath)) {
			yyerror("invalid include file path");
			return (-1);
		}
	}

	fp = fopen(filepath, "r");
	if (fp == NULL) {
		yyerror("cannot open included file");
		return (-1);
	}

	incl = malloc(sizeof(*incl));
	assert(incl != NULL);
	incl->incl_prev = inclp;
	incl->incl_buf = YY_CURRENT_BUFFER;
	incl->incl_fname = yyfile;
	incl->incl_lineno = lineno;
	incl->incl_logfilefd = logfilefd;
	logfilefd = opts.logfd;
	inclp = incl;
	yy_switch_to_buffer(yy_create_buffer(fp, YY_BUF_SIZE));
	yyfile = fname;
	lineno = 0;
	return (0);
}

static void
endinclude(void)
{
	struct incl *incl;

	incl = inclp;
	assert(incl != NULL);

	inclp = incl->incl_prev;
	yy_delete_buffer(YY_CURRENT_BUFFER);
	(void)fclose(yyin);
	yy_switch_to_buffer(incl->incl_buf);
	yyfile = incl->incl_fname;
	lineno = incl->incl_lineno;
	logfilefd = incl->incl_logfilefd;
	free(incl);
}
