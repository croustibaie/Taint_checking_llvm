default: all

all:
	for f in *.c; do \
		clang -g -O0 -emit-llvm $$f -S -o `basename $$f .c`.O0.ll ; \
	done
