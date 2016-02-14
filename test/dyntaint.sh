#!/bin/sh

DEST_LL="/tmp/dest.ll"
DEST_EXE="/tmp/dest"
DEST_TG="/tmp/dest.taintgrind.log"

if [ -z "$1" ]; then
    echo "Usage: dyntaint.sh <bitcode-src>"
    exit 1
fi

SRC="$1"
ARGS=""
shift

for ARG in "$@"; do
    ARGS="$ARGS $SRC"
    SRC="$ARG"
done

$(dirname $0)/asbdetect.sh -asb-log-level 0 -asb_detection_instr_only "$SRC" "$DEST_LL" && \
    clang -g -O0 -o "$DEST_EXE" "$DEST_LL" && \
    valgrind --tool=taintgrind "$DEST_EXE" 2> "$DEST_TG"

exec $(dirname $0)/../process-taintgrind/process-taintgrind-output.rb $ARGS "$DEST_TG"
