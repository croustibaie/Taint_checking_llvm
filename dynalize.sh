#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: dynalize.sh [args] <executable>"
    echo "Args:"
    echo "  -no-cleanup    Don't clean up afterwards leaving the tmp files in /tmp"
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

for ARG in $ARGS; do
    if [ "$ARG" = "-no-cleanup" ]; then
        CLEANUP=0
    else
        PTO_ARGS="$PTO_ARGS $ARG"
    fi
done

# generate random id
#RID=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1`
#BASE="$SRC_$RID"
BASE="$SRC"

DEST_TG="/tmp/$BASE.taintgrind.log"

valgrind --tool=taintgrind --tainted-ins-only=yes ./"$SRC" > /dev/null 2> "$DEST_TG"
$(dirname $0)/process-taintgrind/process-taintgrind-output.rb $PTO_ARGS "$DEST_TG"

if [ $CLEANUP = 1 ]; then
    rm -f "$DEST_TG" 2> /dev/null
fi
