#Makefile

CC=gcc
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg


all:
	gcc -o cxtracker cxtracker.c -lpcap $(DCFLAGS)

opti:
	gcc -o cxtracker cxtracker.c -lpcap $(OCFLAGS)

debug:
	gcc -o cxtracker cxtracker.c -lpcap $(PCFLAGS)

clean:
	rm cxtracker 

