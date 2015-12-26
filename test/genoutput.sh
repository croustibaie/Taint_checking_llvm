#!/bin/sh

F=`basename "$1" .c`
echo $F

cd static-taint
make
cd ..

for i in 0 1 3; do
    ./show-taint.sh static-taint/$F.O$i.bc 2> static-taint/$F.O$i.output
done

exec emacs static-taint/$F.c static-taint/$F.*.output
