#Makefile

OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg
LDFLAGS=-lpcap

all: cxtracker
#gcc -o cxtracker cxtracker.c -lpcap $(OCFLAGS)

debug: 
	gcc -o cxtracker cxtracker.c -lpcap $(DCFLAGS)

profile:
	gcc -o cxtracker cxtracker.c -lpcap $(PCFLAGS)

clean:
	-rm -v cxtracker smallcxt cxtracker.o

