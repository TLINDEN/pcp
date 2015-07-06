#!/bin/sh

(echo "#ifndef _HAVE_USAGE_H"; echo "#define _HAVE_USAGE_H") > usage.h

echo -n "#define PCP_HELP " >> usage.h

cat usage.txt | sed -e 's/^/"/' -e 's/$/\\n" \\/' >> usage.h

printf "\"\"\\n" >> usage.h
echo "#endif" >> usage.h
