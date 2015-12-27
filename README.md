# Detecting address sensitive behavior
This describes how to compile the instrumentation tools, instrument your test program and finally run it to detect address sensitive behaviors.

## Prerequisits
* Download and compile LLVM
* Download and compile [`taintgrind`](https://github.com/wmkhoo/taintgrind).

## Installing the instrumentation pass

```bash
git clone git@github.com:croustibaie/Taint_checking_llvm.git ASBDetection
cd ASBDetection
cmake -DLLVM_DIR=/path/to/llvm-build/share/llvm/cmake .
make
```

## Compile your source files to bitcode

The plugin requires a function named `print`.
A sample function can be found in the `test` folder together with a test program to instrument.
Compile both to bitcode with:
```bash
cd test
./compile.sh print.c print.bc
./compile.sh test.c test.bc
```
*Note:* You probably have to adjust the path to your valgrind installation in `compile.sh`.

*Note:* If you change the return type or the arguments of `print()`, you'll have to change the pass.

Now link the `print.bc` to your instrumented program:
```bash
llvm-link print.bc test.bc -S -o=linked.bc
```

The flag `-S` makes `linked.bc` readable in vi but is not necessary otherwise. In general, to view your bitcode use: 
```bash
llvm-dis linked.bc && less linked.ll
```

## Running the pass and the bitcode

To run the pass on the bitcode:
```bash
opt -S -load ../ASBDetection/libLLVMasbDetection.so -asb_decection < linked.bc > instr.bc
```

To run `instr.bc`:
```bash
lli instr.bc
```

## How-To compile with dataflow sanitizer & intermediate bitcode
The goal here is to compile with the dataflow sanitizer but with an intermediate output of the bitcode representation to allow calls to the `opt` command in between.

Here is how to get the commands needed:

1. Run `clang -fsanitize=dataflow -emit-llvm -c file.c -o file.bc` to generate bitcode
2. Run `clang -v -fsanitize=dataflow file.c` (just to print the commands which we will need to generate object files)
3. An adaption of the first command can be used to compile the bitcode into object code. Change it as follows and run it
   a. Replace `-main-file-name file.c` with `-main-file-name file.bc`
   b. Remove both the `-fsanitize=dataflow` and the `-fsanitize-blacklist=...` option
   c. Change the `-o /tmp/file-*.o` option to `-o file.o`
   d. Change the `-x c` to `-x ir`
   e. Change the file name in the end from `file.c` to `file.bc`
4. Change the file name in the linker command from `/tmp/file-*.o` to `file.o` and run it

For example the commands could look as follows:

```
"/home/cui/gits/master/llvm-build/bin/clang-3.8" -cc1 -triple x86_64-unknown-linux-gnu -emit-obj -mrelax-all -disable-free -main-file-name foo.bc -mrelocation-model pic -pic-level 2 -pie-level 2 -mthread-model posix -mdisable-fp-elim -fmath-errno -masm-verbose -mconstructor-aliases -munwind-tables -fuse-init-array -target-cpu x86-64 -v -dwarf-column-info -resource-dir /home/cui/gits/master/llvm-build/bin/../lib/clang/3.8.0 -internal-isystem /usr/local/include -internal-isystem /home/cui/gits/master/llvm-build/bin/../lib/clang/3.8.0/include -internal-externc-isystem /include -internal-externc-isystem /usr/include -fdebug-compilation-dir /home/cui/gits/master/foo/bar -ferror-limit 19 -fmessage-length 151 -fobjc-runtime=gcc -fdiagnostics-show-option -o foo.o -x ir foo.bc
```

and

```
"/usr/bin/ld" -pie --hash-style=gnu --no-add-needed --build-id --eh-frame-hdr -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o a.out /usr/lib/gcc/x86_64-redhat-linux/5.3.1/../../../../lib64/Scrt1.o /usr/lib/gcc/x86_64-redhat-linux/5.3.1/../../../../lib64/crti.o /usr/lib/gcc/x86_64-redhat-linux/5.3.1/crtbeginS.o -L/usr/lib/gcc/x86_64-redhat-linux/5.3.1 -L/usr/lib/gcc/x86_64-redhat-linux/5.3.1/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/usr/lib/gcc/x86_64-redhat-linux/5.3.1/../../.. -L/home/cui/gits/master/llvm-build/bin/../lib -L/lib -L/usr/lib -whole-archive /home/cui/gits/master/llvm-build/bin/../lib/clang/3.8.0/lib/linux/libclang_rt.dfsan-x86_64.a -no-whole-archive --dynamic-list=/home/cui/gits/master/llvm-build/bin/../lib/clang/3.8.0/lib/linux/libclang_rt.dfsan-x86_64.a.syms foo.o --no-as-needed -lpthread -lrt -lm -ldl -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-redhat-linux/5.3.1/crtendS.o /usr/lib/gcc/x86_64-redhat-linux/5.3.1/../../../../lib64/crtn.o
```

## TODO

To apply `TNT_MAKE_MEM_CHECK`, we need to find a way to first take the address of our cast variable and cast it as a `void*`. We also need the pass to get the size of the variable since `TNT_MAKE_MEM_CHECK` requires both the address and the length.

Also, so far, the pass cannot be run with a `TNT_MAKE_MEM_TAINTED()` because this function contains an `int**` cast to `int`. Generally, the pass can easily fall into an infinite recursion if your `print()` contains a cast instruction.

Two solutions: escape the `int**` to `int` or find a way to not apply the pass on our `print()` function.

## Useful documentation
Helloworld pass:

https://sites.google.com/site/arnamoyswebsite/Welcome/updates-news/llvmpasstoinsertexternalfunctioncalltothebitcode

Tuto inserting a function:

http://llvm.org/releases/2.6/docs/tutorial/JITTutorial2.html
