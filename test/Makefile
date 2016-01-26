.PHONY: static-taint instr clean

DIRS := static-taint instr

default: all

%.static-taint:
	$(MAKE) -C static-taint $*

%.instr:
	$(MAKE) -C instr $*

all: $(addprefix all.,$(DIRS))
clean: $(addprefix clean.,$(DIRS))
