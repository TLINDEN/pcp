#!/bin/sh

rounds=$1

if test -z "$rounds"; then
    rounds=10
fi

make check

log="collisions.log"
name=""
echo "Checking collisions for hash algorithms with ${rounds} rounds:" > $log

for hash in c o f d s; do
    case $hash in
	o) name="OAT";;
	c) name="CRC";;
	s) name="SAX";;
	d) name="DJB";;
	f) name="FNV";;
    esac
    echo -n "Running ${rounds} x ${name} hash ... "
    echo -n "Collisions for ${name}: " >> $log
    ./col -l ${rounds} -${hash} \
	| sort | uniq -c | sort | grep -v "1 " | wc -l \
	>> $log
    echo "done."
done

echo
echo "Review $log for the results."