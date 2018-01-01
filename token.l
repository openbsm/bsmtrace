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
#include "includes.h"
#include "y.tab.h"

#define YY_NO_UNPUT

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
log		return (LOG);
log-channel	return (LOGCHAN);
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
