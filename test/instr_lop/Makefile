.PHONY: clean

default: all

C_FILES := $(wildcard *.c)
CFLAGS := -g -emit-llvm -S

%.O0.ll: %.c
	clang -O0 $(CFLAGS) -o $@ $<

%.O1.ll: %.c
	clang -O1 $(CFLAGS) -o $@ $<

%.O3.ll: %.c
	clang -O3 $(CFLAGS) -o $@ $<

O0: $(C_FILES:.c=.O0.ll)
O1: $(C_FILES:.c=.O1.ll)
O3: $(C_FILES:.c=.O3.ll)

all: O0 O1 O3

clean:
	rm *.ll
