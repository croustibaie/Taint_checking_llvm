#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: show-taint.sh <bitcode-src>"
    exit 1
fi

exec $(dirname $0)/asbdetect.sh -asb_detection_dump_taint "$1"
