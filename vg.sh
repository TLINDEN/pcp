#!/bin/sh
# small valgrind helper to execute unit tests with valgrind

vg="valgrind --leak-check=full --show-reachable=yes"
cmd=$1
shift

if test -z "$cmd"; then
    echo "Usage: $0 <commandline ..>"
    exit 1
else
    if echo "$cmd" | egrep "^\.\." > /dev/null 2>&1; then
	cd tests
    fi
fi

$vg $cmd $* > log 2>&1
less log
rm -f log

