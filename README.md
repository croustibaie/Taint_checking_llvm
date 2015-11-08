# Instrumentation of bitcode with taintgrind instructions for runtime detection of address sensitive behavior

## Installing the instrumentation pass

```bash
cd ~/your-path-to-llvm/lib/Transforms/
git clone git@github.com:croustibaie/Taint_checking_llvm.git ASBDetection
echo add_subdirectory(ASBDetection) >> CMakeLists.txt
```

Compile with ninja.

## Compile your source files to bitcode

The plugin requires a function named `print`. Create a `print.c` file with the `print()` function and compile it with:

`clang -O3 -emit-llvm  print.c -c -o print.bc to generate the bitcode.`

Compile your `main.c` function with the same command line:

`clang -O3 -emit-llvm  a.c -c -o a.bc`

To link `print.bc` to your main bitcode :

`llvm-link print.bc a.bc -S -o=b.bc` (`-S` makes `b.bc` readable in vi, not necessary)

To view your bitcode : 

`llvm-dis b.bc | less`

note: If you change the return type or the arguments of `print()`, you'll have to change the pass.

I already wrote a functional `print.c` and `a.c` in this folder.

## Running the pass and the bitcode

To run the pass on the bitcode:

`opt -load /your-path-to-llvm/clang-llvm/build/lib/LLVMinsertFun.so -bishe_insert <~/Pass-to-your-bitcode/b.bc> b1.bc`

note: The <> around your bitcode is necessary

To run `b1.bc` :

`lli b1.bc`

## TODO

To apply `TNT_MAKE_MEM_CHECK`, we need to find a way to first take the address of our cast variable and cast it as a `void*`. We also need the pass to get the size of the variable since `TNT_MAKE_MEM_CHECK` requires both the address and the length.

We also need to fix the issue described in `taint-checking-issue.txt` (in this folder).

## Useful documentation
Helloworld pass:

https://sites.google.com/site/arnamoyswebsite/Welcome/updates-news/llvmpasstoinsertexternalfunctioncalltothebitcode

Tuto inserting a function:

http://llvm.org/releases/2.6/docs/tutorial/JITTutorial2.html
