DIRS := static-taint instr instr_aop instr_lop instr_cop

.PHONY: $(DIRS) clean

default: all

%.static-taint:
	$(MAKE) -C static-taint $*

%.instr:
	$(MAKE) -C instr $*

%.instr_aop:
	$(MAKE) -C instr_aop $*

%.instr_lop:
	$(MAKE) -C instr_lop $*

%.instr_cop:
	$(MAKE) -C instr_cop $*

all: $(addprefix all.,$(DIRS))
clean: $(addprefix clean.,$(DIRS))
