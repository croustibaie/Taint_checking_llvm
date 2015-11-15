#!/bin/sh

llvm-dis $1 && less `basename $1 .bc`.ll
