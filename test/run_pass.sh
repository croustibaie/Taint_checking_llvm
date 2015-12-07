#!/bin/sh

opt -S -load `dirname $0`/../ASBDetection/libLLVMasbDetection.so -bishe_insert <$1> instr.bc && rm instr.bc
