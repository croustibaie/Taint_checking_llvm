#!/bin/sh

#PROCESS_TOOL=$(dirname $0)/process-taintgrind/process-taintgrind-output.rb
PROCESS_TOOL=$(dirname $0)/tgproc/target/release/tgproc
#PROCESS_TOOL=$(dirname $0)/tgproc/target/debug/tgproc

if [ -z "$1" ]; then
    echo "Usage: dynalize.sh [args] <executable | c-source>"
    echo "Args:"
    echo "  --no-cleanup    Don't clean up afterwards leaving the tmp files in /tmp"
    echo "  All other arguments are directly passed down to the taintgrind processor tgproc."
    echo
    echo "tgproc help"
    echo "==========="
    $PROCESS_TOOL --help
    exit 1
fi

CLEANUP=1
CLEANUP_FILES="" # the files that would be cleaned up

SRC="$1"
ARGS=""
shift

for ARG in "$@"; do
    ARGS="$ARGS $SRC"
    SRC="$ARG"
done

PTO_ARGS=""

for ARG in $ARGS; do
    if [ "$ARG" = "--no-cleanup" ]; then
        CLEANUP=0
    else
        PTO_ARGS="$PTO_ARGS $ARG"
    fi
done

if [[ "$SRC" =~ \.c$ ]]; then
    TMP_BASE=/tmp/`basename "$SRC" .c`
    
    OBJ_ARGS=""
    if [ $CLEANUP = 0 ]; then
        OBJ_ARGS="--no-cleanup"
    fi
    
    OBJ_FILE="$TMP_BASE".o
    echo "Generating instrumented object file..."
    $(dirname $0)/objectize.sh $OBJ_ARGS "$SRC" "$OBJ_FILE"
    
    EXEC="$TMP_BASE"
    echo "Generating executable..."
    $(dirname $0)/link.sh -o "$EXEC" "$OBJ_FILE"
    
    CLEANUP_FILES="$CLEANUP_FILES $OBJ_FILE $EXEC"
else
    TMP_BASE=/tmp/`basename "$SRC"`

    EXEC="$SRC"
    if [[ ! "$SRC" =~ ^/ ]]; then
        EXEC=./"$EXEC"
    fi
fi

if [ $CLEANUP = 1 ]; then
    # generate unique id
    BASE="${TMP_BASE}_$$"
else
    BASE="$TMP_BASE"
fi

DEST_TG="$TMP_BASE.taintgrind.log"
CLEANUP_FILES="$CLEANUP_FILES $DEST_TG"

valgrind --tool=taintgrind --tainted-ins-only=yes "$EXEC" > /dev/null 2> "$DEST_TG"

$PROCESS_TOOL $PTO_ARGS "$DEST_TG"

if [ $CLEANUP = 1 ]; then
    rm -f $CLEANUP_FILES
fi
