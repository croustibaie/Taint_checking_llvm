#!/bin/sh

CLEANUP=1
ARGS=""

while [[ -n "$1" && "$1" != *.c ]]; do
    if [ "$1" = "-no-cleanup" ]; then
        CLEANUP=0
    else
        ARGS="$ARGS $1"
    fi
    shift
done

if [ -z "$1" ]; then
    echo "Usage: objectize.sh [args] <c-file> [object-file]"
    echo "Args:"
    echo "  -no-cleanup    Don't clean up afterwards leaving the tmp files in /tmp"
    echo "  All other arguments are directly passed to the initial compilation of the c source"
    exit 1
fi

SRC="$1"

if [ -z "$2" ]; then
    DEST=`dirname "$SRC"`/`basename "$SRC" .c`.o
else
    DEST="$2"
fi

DEST_BASE=`basename "$DEST" .o`

# generate random id
#RID=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1`
#BASE="$DEST_BASE_$RID"
BASE="$DEST_BASE"

BC1="/tmp/$BASE.bc"
BC2="/tmp/${BASE}.instr.bc"

# if we don't clean up generate human readable llvm IR instead of bitcode
if [ $CLEANUP = 1 ]; then
    CLANG_LLVM_FORMAT_ARG="-c"
    OPT_LLVM_FORMAT_ARG=""
else
    CLANG_LLVM_FORMAT_ARG="-S"
    OPT_LLVM_FORMAT_ARG="-S"
fi

clang -emit-llvm $CLANG_LLVM_FORMAT_ARG $ARGS -o "$BC1" "$SRC" && \
    opt $OPT_LLVM_FORMAT_ARG -load $(dirname $0)/ASBDetection/libLLVMasbDetection.so -asb_detection -asb-log-level 0 -asb_detection_instr_only < "$BC1" > "$BC2" && \
    clang -g -O0 -c -o "$DEST" "$BC2"

if [ $CLEANUP = 1 ]; then
    rm -f "$BC1" "$BC2"
fi
