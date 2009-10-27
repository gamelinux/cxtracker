#Makefile

OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg
LDFLAGS=-lpcap

all: cxtracker
#gcc -o cxtracker cxtracker.c -lpcap $(OCFLAGS)

debug: 
	gcc $(DCFLAGS) -o cxtracker cxtracker.c -lpcap

profile:
	gcc $(PCFLAGS) -o cxtracker cxtracker.c -lpcap

clean:
	-rm -v cxtracker smallcxt cxtracker.o

