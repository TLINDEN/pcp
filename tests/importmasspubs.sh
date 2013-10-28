#!/bin/sh

outdir=$1
pcp=$2
vault=$3

if test -s "$vault"; then
    # imports public keys
    rm -f $vault
fi

ls -1 $outdir/0x* | while read id; do
    $pcp -V $vault -P -I $id
done
