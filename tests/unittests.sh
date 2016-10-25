#!/bin/sh

errout () {
    logout="$1"
    expect="$2"
    echo "  EXPECTED: $expect"
    echo -n "       GOT: "
    cat $logout | head -1
    cat $logout | tail -n +2 | sed 's/^/            /'
}


lookup () {
    logfile="$1"
    expect="$2"

    if echo "$expect" | grep '!' > /dev/null 2>&2; then
        # negate
        expect=`echo "$expect" | sed -e 's/^\!//' -e 's#^/##' -e 's#/$##'`
        if cat $logfile | grep -i "$expect" > /dev/null 2>&1; then
            errout "$logfile" "NOT $expect"
            return 1
        else
           echo "  OK"
           return 0
        fi  
    else
        expect=`echo "$expect" | sed -e 's#^/##' -e 's#/$##'`
        if cat $logfile | grep -i "$expect" > /dev/null 2>&1; then
            echo "  OK"
            return 0
        else
            errout "$logfile" "$expect"
            return 1
        fi
    fi
}

check() {
    cmd="$1"
    expect="$2"
    input="$3"
    file="$4"
    log=".log-$$"
    fail=''

    echo "  executing $cmd"

    echo "$input" | eval "$cmd" > $log 2>&1

    if test -n "$file"; then
        # ignore result, check output file
        if test -n "$expect"; then
            # look for string in output
            if ! lookup "$file" "$expect"; then
                fail=y
            fi
        else
            # just check for existence
            if test -e "$file"; then
                echo "  OK"
            else
                echo "  Failed: $file doesnt exist"
                fail=y
            fi
        fi
    else
        # check output
        if ! lookup "$log" "$expect"; then
            fail=y
        fi
    fi

    rm -f $log

    if test -n "$fail"; then
        return 1
    else
        return 0
    fi
}

checkdump () {
    F="$1"
    if test -e "pcp1.core"; then
        echo "Test $F dumped core!"
        gdb -x .gdb -batch $pcp pcp1.core
        exit 1
    fi
}

callcheck () {
    F="$1"
    rm -f pcp1.core
    echo "--- test $F result:"
    if ! $F; then
        echo
        echo "Test $F failed!"
        checkdump $F
        exit 1
    else
        checkdump $F
    fi
}

cfg="$1"
check="$2"

if test -z "$cfg"; then
    echo "Usage: $0 <config> [check]"
    exit 1
fi

if ! test -e "$cfg"; then
    echo "$cfg doesn't exist!"
    exit 1
fi

. ./$cfg

count=`grep -E -- "^check_" "$cfg" | wc -l`

callcheck prepare

if test -n "$check"; then
    callcheck $check
else
    for F in `grep -E -- "^check_" "$cfg" | cut -d' ' -f1`; do
        callcheck $F
    done
    echo "All Tests OK"
fi

