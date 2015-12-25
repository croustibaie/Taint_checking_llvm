#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: show_taint.sh <bitcode-src>"
    exit 1
fi

opt -S -load `dirname $0`/../ASBDetection/libLLVMasbDetection.so -asb_detection -asb_detection_dump_taint < $1 > /dev/null
