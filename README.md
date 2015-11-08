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
opt -S -load ../ASBDetection/libLLVMasbDetection.so -bishe_insert <linked.bc> instr.bc
```
*Note:* The <> around your bitcode is necessary

To run `instr.bc`:
```bash
lli instr.bc
```

## TODO

To apply `TNT_MAKE_MEM_CHECK`, we need to find a way to first take the address of our cast variable and cast it as a `void*`. We also need the pass to get the size of the variable since `TNT_MAKE_MEM_CHECK` requires both the address and the length.

We also need to fix the issue described in `taint-checking-issue.txt` (in this folder).

## Useful documentation
Helloworld pass:

https://sites.google.com/site/arnamoyswebsite/Welcome/updates-news/llvmpasstoinsertexternalfunctioncalltothebitcode

Tuto inserting a function:

http://llvm.org/releases/2.6/docs/tutorial/JITTutorial2.html
