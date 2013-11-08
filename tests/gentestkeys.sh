#!/bin/sh
pcp="../src/pcp1 -V vxxx"

(echo Alicia; echo alicia@local) | $pcp -k -x a
(echo Bobby;  echo bobby@local)  | $pcp -k -x b
(echo Bart;   echo bart@local)   | $pcp -k -x a


ida=`$pcp -l | grep Alicia | awk '{print $1}'`
idb=`$pcp -l | grep Bobby  | awk '{print $1}'`
ids=`$pcp -l | grep Bart   | awk '{print $1}'`

$pcp -p -O key-alicia-pub -i $ida
$pcp -s -O key-alicia-sec -i $ida
$pcp -p -O key-bobby-pub -i $idb
$pcp -s -O key-bobby-sec -i $idb
$pcp -p -O bart.pub -i $ids

ser=`grep Serial bart.pub | awk '{print $3}'`

echo "bartid = $ids
bartserial = $ser
idbobby  = $idb
idalicia = $ida
mailbobby = bobby@local
mailalicia = alicia@local" > keys.cfg

rm -f vxxx
