#!/bin/sh

outdir=$1
pcp=$2
vault=$3

if test -s "$vault"; then
    # exports public keys
    rm -f $outdir/0x*
    $pcp -V $vault -l | grep 0x | awk '{print $1}' | while read id; do
	$pcp -V $vault -p -i $id 2> /dev/null | egrep -v "^ " \
	    | egrep -v '^$' > $outdir/$id 
    done
fi