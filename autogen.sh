#!/bin/sh

mode=config

case $1 in
    clean)
	mode=clean
	;;
    gen)
	mode=gen
	;;
    -h|--help|help|\?)
	echo "Usage: $0 [clean|gen]"
	exit 1
	;;
esac


if test "$mode" = "gen"; then
    # generate the install include file
    (echo "#ifndef _HAVE_PCP"; echo "#define _HAVE_PCP"; echo) > include/pcp.h
    (echo "#ifdef __cplusplus"; echo "extern \"C\" {"; echo "#endif"; echo) >> include/pcp.h
    echo "#include \"pcp/config.h\"" >> include/pcp.h

    ls include/pcp/*.h | sed 's#include/##' | while read include; do
	echo "#include \"$include\"" >> include/pcp.h
    done

    (echo "#ifdef __cplusplus"; echo "}"; echo "#endif"; echo) >> include/pcp.h
    (echo; echo "#endif") >> include/pcp.h


    # generate the version file
    maj=`egrep "#define PCP_VERSION_MAJOR" include/pcp/version.h | awk '{print $3}'`
    min=`egrep "#define PCP_VERSION_MINOR" include/pcp/version.h | awk '{print $3}'`
    pat=`egrep "#define PCP_VERSION_PATCH" include/pcp/version.h | awk '{print $3}'`
    echo -n "$maj.$min.$pat" > VERSION

    # generate the manpage
    echo "=head1 NAME

Pretty Curved Privacy - File encryption using eliptic curve cryptography.

=head1 SYNOPSIS

" > man/pcp1.pod
    cat src/usage.txt | sed "s/^/  /g" >> man/pcp1.pod
    cat man/options.pod >> man/pcp1.pod
    cat man/pcp.pod >> man/pcp1.pod
    cat man/details.pod >> man/pcp1.pod
    cat man/footer.pod >> man/pcp1.pod

    pod2man -r "PCP `cat VERSION`" -c "USER CONTRIBUTED DOCUMENTATION" man/pcp1.pod > man/pcp1.1

    # generate the top level readme
    cat man/pcp.pod man/install.pod man/footer.pod > README.pod
    pod2text README.pod > README

    # generate usage.h
    (cd src && ./usage.sh)

    # generate pypcp types
    bindings/py/gencffi.pl include/pcp/defines.h include/pcp/structs.h include/pcp/key.h \
	                   include/pcp/buffer.h include/pcp/context.h \
	                   include/pcp/ed.h include/pcp/crypto.h include/pcp/vault.h \
	                   include/pcp/mgmt.h include/pcp/keyhash.h \
	                   include/pcp/pcpstream.h include/pcp/z85.h > bindings/py/pypcp/raw.py
    cd -

    exit
fi



if test "$mode" = "config"; then
  mkdir -p ./config
  
  if ! command -v libtool >/dev/null 2>&1; then
      echo "could not find libtool." 1>&2
      exit 1
  fi
  
  if ! command -v autoreconf >/dev/null 2>&1; then
      echo "could not find autoreconf." 1>&2
      exit 1
  fi
  
  autoreconf --install --force --verbose -I config
fi


#
# normal autogen stuff

cat <<EOF > clean.sh
#!/bin/sh
find . -name Makefile    -exec rm {} \;      > /dev/null 2>&1
find . -name Makefile.in -exec rm {} \;      > /dev/null 2>&1
find . -name "*~"        -exec rm {} \;      > /dev/null 2>&1
find . -name config.h    -exec rm {} \;      > /dev/null 2>&1
find . -name "stamp*"    -exec rm {} \;      > /dev/null 2>&1
find . -name .deps       -exec rm -rf {} \;  > /dev/null 2>&1
find . -name .libs       -exec rm -rf {} \;  > /dev/null 2>&1
find . -name .o          -exec rm -rf {} \;  > /dev/null 2>&1
find . -name .lo         -exec rm -rf {} \;  > /dev/null 2>&1
find . -name .pyc        -exec rm -rf {} \;  > /dev/null 2>&1
find . -name .dirstamp   -exec rm -rf {} \;  > /dev/null 2>&1
rm -rf aclocal.m4 libtool configure config.* config autom4te.cache tests/test* tests/v* tests/stresstest/* libpcp/libpcp1.pc
rm clean.sh
EOF

chmod 700 clean.sh


rm -rf include/pcp/config.h.in~ libpcp/stamp-h1 autom4te.cache

sleep 1
touch Makefile.in configure */Makefile.in
