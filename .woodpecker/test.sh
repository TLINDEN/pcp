#!/bin/bash

yq '.steps.test-gdbm.commands' < .woodpecker/build.yaml \
    | grep -- - | grep -v apk | sed 's/^\- //' \
 | while read COMMAND; do
    echo "$COMMAND" | bash -e > debug.log 2>&1
    if test $? -ne 0; then
        echo "fail - $COMMAND"
        if test -s debug.log; then
            cat debug.log
        else
            echo exit 1
        fi
    else
        echo "ok   - $COMMAND"
    fi
done

rm -f debug.log
