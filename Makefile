# Makefile for lreg

CC = gcc -Wall -g -DDEBUG
PROGNAME = lreg 
MODULES = lisp.o net.o

.PHONY: all

all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

lreg: lreg.c $(MODULES)
	$(CC) lreg.c -lssl $(MODULES) -o lreg

clean:
	rm $(PROGNAME) $(MODULES)

lisp.o: lisp.h lisp.c
net.o : net.h net.c
