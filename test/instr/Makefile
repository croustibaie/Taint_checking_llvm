default: all

all:
	for f in *.c; do \
		clang -g -O0 -emit-llvm $$f -S -o `basename $$f .c`.O0.ll ; \
		clang -g -O1 -emit-llvm $$f -S -o `basename $$f .c`.O1.ll ; \
		clang -g -O3 -emit-llvm $$f -S -o `basename $$f .c`.O3.ll ; \
	done
