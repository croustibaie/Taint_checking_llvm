#!/bin/sh

DEST="/tmp/dest.ll"

if [ -z "$1" ]; then
    echo "Usage: show-instr.sh <bitcode-src> [dest=$DEST]"
    exit 1
fi

if [ -n "$1" ]; then
    DEST="$1"
fi

cat "$1"
echo
echo "---------------------------------------------------------------------"
echo

$(dirname $0)/asbdetect.sh -asb_detection_instr_only "$1" "$DEST"
cat "$DEST"
