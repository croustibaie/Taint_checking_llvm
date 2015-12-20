#!/bin/sh

llvm-dis $1 && less `dirname $1`/`basename $1 .bc`.ll
