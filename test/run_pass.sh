#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: run_pass.sh <bitcode-src>"
    exit 1
fi

opt -S -load `dirname $0`/../ASBDetection/libLLVMasbDetection.so -bishe_insert <$1> instr.bc && rm instr.bc
