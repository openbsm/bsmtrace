# $Id$

CC	?= cc
CFLAGS 	= -Wall -g -DAUDITPIPE_GET_DROPS
TARGETS = bsmtrace
OBJ	= pipe.o y.tab.o bsm.o bsmtrace.o conf.o lex.yy.o log.o trigger.o fcache.o
PREFIX	?= /usr/local
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

.ORDER:	clean bsmtrace install
.ORDER:	deinstall install

install:
	[ -d $(PREFIX)/bin ] || mkdir -p $(PREFIX)/bin
	install -m 0555 bsmtrace $(PREFIX)/bin
	[ -d $(PREFIX)/etc ] || mkdir -p $(PREFIX)/etc
	install -m 0600 bsmtrace.conf $(PREFIX)/etc
	[ -d $(PREFIX)/share/man/man1/ ] || mkdir -p $(PREFIX)/share/man/man1/
	install -m 0444 bsmtrace.1 $(PREFIX)/share/man/man1/
	[ -d $(PREFIX)/share/man/man5/ ] || mkdir -p $(PREFIX)/share/man/man5/
	install -m 0444 bsmtrace.conf.5 $(PREFIX)/share/man/man5/

deinstall:
	rm -fr $(PREFIX)/bin/bsmtrace
	rm -fr $(PREFIX)/share/man/man1/bsmtrace.1
	rm -fr $(PREFIX)/share/man/man5/bsmtrace.conf.5

clean:
	rm -f $(TARGETS) *.o *~ \#* *.core ktrace.out lex.yy.c y.tab.* y.output
