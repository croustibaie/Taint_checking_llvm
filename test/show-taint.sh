#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: show-taint.sh <bitcode-src>"
    exit 1
fi

exec ./asbdetect.sh -asb_detection_dump_taint "$1"
