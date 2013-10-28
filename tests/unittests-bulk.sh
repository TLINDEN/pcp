#!/bin/sh

pcp=$1
vault=$2
log=$3
count=$4

rm -f $vault

jot $count | while read x; do
    (echo x; echo y;) | $pcp -V $vault -k -x bbb
done > $log 2>&1

