.PHONY: clean

default: all

BUILD_TOOLS_DIR := ../..
C_FILES := $(wildcard *.c)

%.O0.o: %.c
	$(BUILD_TOOLS_DIR)/objectize.sh -O0 $< $@

%.O1.o: %.c
	$(BUILD_TOOLS_DIR)/objectize.sh -O0 $< $@

%.O3.o: %.c
	$(BUILD_TOOLS_DIR)/objectize.sh -O0 $< $@

%.O0: %.O0.o
	$(BUILD_TOOLS_DIR)/link.sh -o $@ $<

%.O1: %.O1.o
	$(BUILD_TOOLS_DIR)/link.sh -o $@ $<

%.O3: %.O3.o
	$(BUILD_TOOLS_DIR)/link.sh -o $@ $<

O0: $(C_FILES:.c=.O0)
O1: $(C_FILES:.c=.O1)
O3: $(C_FILES:.c=.O3)

all: O0 O1 O3

clean:
	rm -f *.o *.O[013] *~
