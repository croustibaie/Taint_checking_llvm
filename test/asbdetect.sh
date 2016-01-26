#!/bin/sh

while [[ -n "$1" && "$1" != *.ll && "$1" != *.bc ]]; do
    ARGS="$ARGS $1"
    shift
done

if [ -z "$1" ]; then
    echo "Usage: asbdetect.sh [args] <bitcode-src> [instrumented dest]"
    exit 1
fi

if [ -n "$2" ]; then
    DEST="$2"
else
    DEST=/dev/null
fi

opt -S -load `dirname $0`/../ASBDetection/libLLVMasbDetection.so -asb_detection $ARGS < "$1" > "$DEST"
