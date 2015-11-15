#!/bin/sh

./compile.sh print.c print.bc
./compile.sh test.c test.bc
llvm-link print.bc test.bc -S -o=linked.bc
opt -S -load ../ASBDetection/libLLVMasbDetection.so -bishe_insert <linked.bc> instr.bc

if [ -n "$1" ]; then
    # run the code
    echo "----------------------------------------------------------------------"
    exec lli instr.bc
fi
