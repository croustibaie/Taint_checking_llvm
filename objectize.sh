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
    echo "Usage: objectize.sh [compilation arguments] <c-file> [object-file]"
    echo "Args:"
    echo "  -no-cleanup    Don't clean up afterwards leaving the tmp files in /tmp"
    echo "  All other arguments are directly passed to the initial compilation of the c source"
    exit 1
fi

SRC="$1"
SRC_BASE=`basename "$SRC" .c`

if [ -z "$2" ]; then
    DEST=`dirname "$SRC"`/"$SRC_BASE".o
else
    DEST="$2"
fi

# generate random id
#RID=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1`
#BASE="$SRC_BASE_$RID"
BASE="$SRC_BASE"

BC1="/tmp/$BASE.bc"
BC2="/tmp/${BASE}.instr.bc"

clang -emit-llvm -c $ARGS -o "$BC1" "$SRC" && \
    opt -S -load $(dirname $0)/ASBDetection/libLLVMasbDetection.so -asb_detection -asb-log-level 0 -asb_detection_instr_only < "$BC1" > "$BC2" && \
    clang -g -O0 -c -o "$DEST" "$BC2"

if [ $CLEANUP = 1 ]; then
    rm -f "$BC1" "$BC2"
fi
