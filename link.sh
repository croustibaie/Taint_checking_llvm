#!/bin/sh

WRAPPERS_DIR=$(dirname "$0")/wrappers

if [ -z "$1" ]; then
    echo "Usage: link.sh [link-flags] <obj-files>*"
    exit 1
fi

exec clang -g -O0 -Wl,-wrap,malloc,-wrap,realloc,-wrap,calloc,-wrap,write $@ "$WRAPPERS_DIR"/libc_wrapper.o
