#Makefile
CC=gcc

OCFLAGS=-g -O3
DCFLAGS=-g
PCFLAGS=-g -pg
LIBS=-lpcap
LDFLAGS=

SRC= cxtracker.c cxtracker.h \
format.c format.h \
ip.c ip.h

OBJS= ip.o format.o cxtracker.o

TARGETS=cxtracker

all:${TARGETS}

cxtracker: $(OBJS)
	$(CC) $(OBJS) -o cxtracker $(LIBS) $(LDFLAGS)

debug: $(OBJS)
	$(CC) $(OBJS) -o cxtracker $(DCFLAGS) $(LDFLAGS)

profile: $(OBJS)
	$(CC) $(OBJS) -o cxtracker $(RCFLAGS) $(LDFLAGS)

clean:
	-rm -f ${OBJS} ${TARGETS}

.c.o:
	$(CC) -c -Wall $(DEFS) $(OCFLAGS) $<

