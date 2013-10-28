#!/bin/sh

outdir=$1
number=$2
pcp=$3
vault=$4

mkdir -p $outdir

if test -s $vault; then
    has=`$pcp -V $vault -l 2>/dev/null | grep 0x | wc -l | awk '{print $1}'`
    if test $has -eq $number; then
	exit
    fi
    rm -f $vault
fi

# generates $number secret keys
jot $number | while read x; do
    count=`jot -r 1 10 127`
    name=`openssl rand -hex $count`
    mail=`openssl rand -hex $count`
    (echo $name; echo $mail;) | $pcp -V $vault -k -x xxx > /dev/null 2>&1
done

# exports public keys
$pcp -V $vault -l | grep 0x | awk '{print $1}' | while read id; do
    $pcp -V $vault -p -i $id 2> /dev/null | egrep -v "^ " | \
	egrep -v '^$' > $outdir/$id 
done
