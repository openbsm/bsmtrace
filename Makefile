# $Id$

CC	?= cc
CFLAGS 	= -Wall -g -DAUDITPIPE_GET_DROPS
TARGETS = bsmtrace
OBJ	= pipe.o y.tab.o bsm.o bsmtrace.o conf.o lex.yy.o log.o trigger.o fcache.o
PREFIX	= /usr/local
LIBS	= -lbsm

CFLAGS	+= -I /usr/local/include
CFLAGS	+= -D PCRE
LIBS	+= -lpcre -L/usr/local/lib

all: $(TARGETS)

.c.o:
	$(CC) $(CFLAGS) -c $<

y.tab.o: grammar.y
	yacc -vd grammar.y
	$(CC) $(CFLAGS) -c y.tab.c

y.tab.h: y.tab.o

lex.yy.o: y.tab.h token.l
	lex token.l
	$(CC) $(CFLAGS) -c lex.yy.c

bsmtrace: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

bsmtrace.1.gz:
	gzip -k bsmtrace.1

bsmtrace.conf.5.gz:
	gzip -k bsmtrace.conf.5

install: bsmtrace bsmtrace.1.gz bsmtrace.conf.5.gz
	install -m 0555 -o root -g wheel bsmtrace $(PREFIX)/bin
	install -m 0600 -o root -g wheel bsmtrace.conf $(PREFIX)/etc
	install -m 0444 -o root -g wheel bsmtrace.1.gz $(PREFIX)/share/man/man1/
	install -m 0444 -o root -g wheel bsmtrace.conf.5.gz $(PREFIX)/share/man/man5/

deinstall:
	rm -fr $(PREFIX)/bin/bsmtrace
	rm -fr $(PREFIX)/share/man/man1/bsmtrace.1.gz
	rm -fr $(PREFIX)/share/man/man5/bsmtrace.conf.5.gz

clean:
	rm -f $(TARGETS) *.o *~ \#* *.core ktrace.out lex.yy.c y.tab.* y.output bsmtrace.1.gz bsmtrace.conf.5.gz
