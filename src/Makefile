#Makefile

OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg
LDFLAGS=-lpcap

all:
	gcc $(OCFLAGS) -o cxtracker cxtracker.c -lpcap

debug: 
	gcc $(DCFLAGS) -o cxtracker cxtracker.c -lpcap

profile:
	gcc $(PCFLAGS) -o cxtracker cxtracker.c -lpcap

clean:
	-rm -v cxtracker smallcxt cxtracker.o

