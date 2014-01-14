# $Id$

CC	?= cc
CFLAGS 	= -Wall -g
TARGETS = bsmtrace
OBJ	= y.tab.o bsm.o bsmtrace.o conf.o lex.yy.o log.o pipe.o trigger.o fcache.o
PREFIX	= /usr/local
LIBS	= -lbsm

#.ifdef PCRE
#CFLAGS	+= -I /usr/local/include
#CFLAGS	+= -L /usr/local/lib
#CFLAGS	+= -D PCRE
#LIBS	+= -lpcre
#.endif

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

#doc: bsmtrace.man bsmtrace.conf.man
#	cp -f bsmtrace.man bsmtrace.1
#	cp -f bsmtrace.conf.man bsmtrace.conf.5
#	gzip -f bsmtrace.1 bsmtrace.conf.5

install:
	strip bsmtrace
	install -m 0555 -o root -g wheel bsmtrace $(PREFIX)/sbin
	install -m 0600 -o root -g wheel bsmtrace.conf $(PREFIX)/etc
#	install -m 0444 -o root -g wheel bsmtrace.1.gz /usr/share/man/man1/
#	install -m 0444 -o root -g wheel bsmtrace.conf.5.gz /usr/share/man/man5/

deinstall:
	rm -fr $(PREFIX)/sbin/bsmtrace

clean:
	rm -f $(TARGETS) *.o *~ \#* *.core ktrace.out lex.yy.c y.tab.* y.output bsmtrace.1.gz bsmtrace.conf.5.gz
