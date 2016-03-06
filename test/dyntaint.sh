#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: dyntaint.sh [args] <bitcode-src>"
    echo "Args:"
    echo "  -dt-noclean    Don't clean up afterwards leaving the tmp files in /tmp"
    echo "  All other arguments are directly passed down to process-taintgrind-output"
    exit 1
fi

CLEANUP=1

SRC="$1"
ARGS=""
shift

for ARG in "$@"; do
    ARGS="$ARGS $SRC"
    SRC="$ARG"
done

PTO_ARGS=""

for ARG in "$ARGS"; do
    ARG_STRIPPED=`echo $ARG`
    if [ "$ARG_STRIPPED" = "-dt-noclean" ]; then
        CLEANUP=0
    else
        PTO_ARGS="$PTO_ARGS $ARG"
    fi
done

SRC_BASE=`basename "$SRC" .ll`

# generate random id
#RID=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1`
#BASE="$SRC_BASE_$RID"
BASE="$SRC_BASE"

DEST_LL="/tmp/$BASE.ll"
DEST_EXE="/tmp/$BASE"
DEST_TG="/tmp/$BASE.taintgrind.log"

$(dirname $0)/asbdetect.sh -asb-log-level 0 -asb_detection_instr_only "$SRC" "$DEST_LL" && \
    clang -g -O0 -o "$DEST_EXE" "$DEST_LL" && \
    valgrind --tool=taintgrind --tainted-ins-only=yes "$DEST_EXE" 2> "$DEST_TG"

$(dirname $0)/../process-taintgrind/process-taintgrind-output.rb $PTO_ARGS "$DEST_TG"

if [ $CLEANUP = 1 ]; then
    rm "$DEST_LL" "$DEST_EXE" "$DEST_TG"
fi
