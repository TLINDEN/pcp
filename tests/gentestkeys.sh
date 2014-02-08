#!/bin/sh
pcp1="../src/pcp1"
pcp="$pcp1 -V vxxx"

rm -f vxxx unknown*

gen() {
    owner=$1
    mail=$2
    pass=$3
    z=$4
    pub=$5
    sec=$6

    (echo $owner; echo $mail) | $pcp -k -x $pass > /dev/null 2>&1

    id=`$pcp -l | grep $owner | awk '{print $1}'`


    if test -n "$pub"; then
	if test "x$z" = "xy"; then
	    $pcp -p -i $id | egrep -v "^ " | egrep -v -- "----" | grep . > $pub
	else
	    $pcp -p -O $pub -i $id > /dev/null 2>&1
	fi
    fi

    if test -n "$sec"; then
	if test "x$z" = "xy"; then
	    $pcp -s -i $id | egrep -v "^ " | egrep -v -- "----" | grep . > $sec
	else
	    $pcp -s -O $sec -i $id > /dev/null 2>&1
	fi
    fi

    echo $id
}


ida=`gen Alicia alicia@local a n key-alicia-pub key-alicia-sec`
idb=`gen Bobby  bobby@local  b n key-bobby-pub key-bobby-sec`
ids=`gen Bart   bart@local   a n bart.pub`
ser=`grep Serial bart.pub | awk '{print $3}'`

gen Niemand niemand@local n y unknown1 unknown2
$pcp1 -V unknown3 -l
echo hallo | $pcp -e -x a -z | egrep -v "^ " | egrep -v -- "----"  | grep . > unknown4
echo blah | $pcp -g -x a | egrep -v "^ " | egrep -v -- "----"  | grep . > unknown5

echo "bartid = $ids
bartserial = $ser
idbobby  = $idb
idalicia = $ida
mailbobby = bobby@local
mailalicia = alicia@local" > keys.cfg

./gencheader > static.h

rm -f vxxx
