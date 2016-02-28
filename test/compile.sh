#!/bin/sh

VALGRIND_DIR=/home/cui/gits/master/valgrind-3.11.0/inst

if [ -z "$1" ]; then
    echo "Usage: ./compile.sh <file.c> [outfile.bc]"
    exit 1
fi

if [ -z "$2" ]; then
    OUTFILE=`basename $1 .c`.ll
else
    OUTFILE="$2"
fi

exec clang -O0 -g -emit-llvm -I$VALGRIND_DIR/include/valgrind $1 -S -o $OUTFILE
