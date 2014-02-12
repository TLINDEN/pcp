#!/bin/sh
pcp1="../src/pcp1"
pcp="$pcp1"

rm -f vxxx* unknown*

gen() {
    owner=$1
    mail=$2
    pass=$3
    z=$4
    pub=$5
    sec=$6

    (echo $owner; echo $mail) | $pcp -V vxxx$owner -k -x $pass

    id=`$pcp -V vxxx$owner -l | grep $owner | awk '{print $1}'`

    zopt=""
    if test "x$z" = "xy"; then
	zopt=" -z "
    fi

    if test -n "$pub"; then
	$pcp -V vxxx$owner -p -O $pub -i $id -x $pass $zopt
    fi

    if test -n "$sec"; then
	$pcp -V vxxx$owner -s -O $sec -i $id -x $pass $zopt
    fi

    echo $id
}


ida=`gen Alicia alicia@local a y key-alicia-pub key-alicia-sec`
idb=`gen Bobby  bobby@local  b y key-bobby-pub key-bobby-sec`
ids=`gen Bart   bart@local   a y bart.pub`
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

rm -f vxxx*
