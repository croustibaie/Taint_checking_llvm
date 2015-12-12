default: all

all:
	for f in *.c; do \
		clang -g -O0 -emit-llvm $$f -c -o `basename $$f .c`.O0.bc ; \
		clang -g -O1 -emit-llvm $$f -c -o `basename $$f .c`.O1.bc ; \
		clang -g -O3 -emit-llvm $$f -c -o `basename $$f .c`.O3.bc ; \
	done
