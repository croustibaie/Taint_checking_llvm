.PHONE: clean

default: all

SRC=$(wildcard *.c)
VALGRIND_BASE=../../valgrind-3.11.0

all: $(SRC)
	gcc -c -O0 -I $(VALGRIND_BASE)/include/ -I $(VALGRIND_BASE)/taintgrind/ $^

clean: 
	rm -f *.o
