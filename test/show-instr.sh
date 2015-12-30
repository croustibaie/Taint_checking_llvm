#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: show-instr.sh <bitcode-src>"
    exit 1
fi

./asbdetect.sh -asb_detection_instr_only "$1" "/tmp/dest.ll"
#cat /tmp/dest.ll
