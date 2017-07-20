#Makefile

OCFLAGS=-g -O3 -Wall -Wextra
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
	$(CC) $(OBJS) -o cxtracker $(LIBS) $(DCFLAGS) $(LDFLAGS)

profile: $(OBJS)
	$(CC) $(OBJS) -o cxtracker $(LIBS) $(PCFLAGS) $(LDFLAGS)

clean:
	-rm -f ${OBJS} ${TARGETS}

.c.o:
	$(CC) -c -Wall $(DEFS) $(OCFLAGS) $<

