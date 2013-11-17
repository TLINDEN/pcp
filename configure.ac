# -*-sh-*-
#
#    This file is part of Pretty Curved Privacy (pcp1).
#
#    Copyright (C) 2013 T.Linden.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    You can contact me by mail: <tlinden AT cpan DOT org>.
#

AC_PREREQ(2.61)

define([pcpversion], esyscmd([sh -c "cat VERSION"]))dnl
AC_INIT([pcp], [pcpversion], [pcp@daemon.de])
#AC_INIT(pcp, `cat VERSION`)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)

AC_CONFIG_HEADER(include/pcp/config.h)
AM_INIT_AUTOMAKE
LT_INIT

ORIG_CFLAGS="${CFLAGS:-none}"

# Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_SED
AC_PROG_AWK
AC_PROG_INSTALL




# Host speciffic checks
AC_CANONICAL_HOST

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(errno.h err.h stdlib.h string.h unistd.h stdio.h getopt.h\
                 limits.h stddef.h stdint.h sys/types.h sys/stat.h endian.h \
                 sys/endian.h termios.h arpa/inet.h netinet/in.h wctype.h)

AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS( \
    arc4random_buf \
    fread \
    fopen \
    free \
    fwrite \
    fseek \
    ftruncate \
    fprintf \
    isatty \
    malloc \
    memset \
    memcpy \
    perror \
    strnlen \
    strlen \
    strtol \
    sizeof \
    tcgetattr \
    be32toh \
    htobe32 \
    umask \
    towlower \
    getopt_long \
    vasprintf
)

AC_MSG_CHECKING([compiler and flags for sanity])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]], [[ exit(0); ]])],
        [       AC_MSG_RESULT([yes]) ],
        [
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([*** compiler cannot create working executables, check config.log ***])
        ],
        [       AC_MSG_WARN([cross compiling: not checking compiler sanity]) ]
)

_havenacl=no
_ldlib=""

AC_ARG_WITH([libsodium],
            [AS_HELP_STRING([--with-libsodium],
                            [Specify libsodium prefix])],
            [search_libsodium="yes"],
            [])

if test "x$search_libsodium" = "xyes"; then
    if test -r "${with_libsodium}/include/sodium.h"; then
        CFLAGS="-I${with_libsodium}/include ${CFLAGS}"
        LDFLAGS="-L${with_libsodium}/lib ${LDFLAGS}"
        _havenacl=yes
	_ldlib="${with_libsodium}/lib"
    fi
fi

AC_ARG_WITH([libsodium-include-dir],
            [AS_HELP_STRING([--with-libsodium-include-dir],
                            [Specify libsodium include prefix])],
            [search_libsodium_include="yes"],
            [])

if test "x$search_libsodium_include" = "xyes"; then
    if test -r "${with_libsodium_include_dir}/sodium.h"; then
        CFLAGS="-I${with_libsodium_include_dir}/include ${CFLAGS}"
	_havenacl=yes
    fi
fi

AC_ARG_WITH([libsodium_lib_dir],
            [AS_HELP_STRING([--with-libsodium-lib-dir],
                            [Specify libsodium library prefix])],
            [search_libsodium_lib="yes"],
            [])

if test "x$search_libsodium_lib" = "xyes"; then
    if test -r "${with_libsodium_lib_dir}/libsodium.{a|so|dylib}"; then
        LDFLAGS="-L${with_libsodium}/lib ${LDFLAGS}"
	_havenacl=yes
	_ldlib="${with_libsodium}/lib"
    fi
fi

if test "x${_havenacl}" = "xno"; then
	AC_MSG_CHECKING([pkg-config for libsodium])
	if pkg-config --exists libsodium; then
		# found it
		LDFLAGS=`pkg-config --libs libsodium`
		CFLAGS=`pkg-config --cflags libsodium`
		_ldlib=`pkg-config --libs libsodium | cut -d ' ' -f 1 | cut -d L -f 2`
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
fi


# Check for some target-specific stuff
case "$host" in
    *aix*)
	# libm is required as well
	CFLAGS="$CFLAGS -D_AIX_SOURCE=1"
	LDFLAGS="$LDFLAGS -lm"
	;;
    *-*-android*) ;;
    *-*-cygwin*) ;;
    *-*-dgux*) ;;
    *-*-darwin*) ;;
    *-*-dragonfly*) ;;
    *-*-haiku*) ;;
    *-*-hpux*) ;;
    *-*-irix5*) ;;
    *-*-irix6*) ;;
    *-*-k*bsd*-gnu | *-*-kopensolaris*-gnu) ;;
    *-*-linux*) ;;
    *-*-netbsd*) ;;
    *-*-freebsd*)
	# ports install to /usr/local by default, check
	if test -d "/usr/local/lib" -a -d "/usr/local/include"; then
	    CFLAGS="$CFLAGS -I/usr/local/include"
	    LDFLAGS="$LDFLAGS -L/usr/local/lib"
	fi
	;;
    *-*-bsdi*) ;;
    *-next-*) ;;
    *-*-openbsd*) ;;
    *-*-solaris*) ;;
    *-*-sunos4*) ;;
    *-ncr-sysv*) ;;
    *-sni-sysv*) ;;
    *-*-sysv4.2*) ;;
    *-*-sysv5*) ;;
    *-*-sysv*) ;;
    *-*-sco*) ;;
    *-*-unicos*) ;;
    *-dec-osf*) ;;
    *-*-nto-qnx*) ;;
    *-*-ultrix*) ;;
    *-*-lynxos) ;;
esac

AC_CHECK_LIB(sodium, sodium_init, , [AC_MSG_ERROR([cannot link with -lsodium, install libsodium.])])

if test -n "$_ldlib"; then
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${_ldlib}"
fi

AC_MSG_CHECKING([is libsodium compiled correctly])
AC_RUN_IFELSE([
AC_LANG_PROGRAM([[
#include <sodium.h>
#if crypto_box_PUBLICKEYBYTES != 32 || crypto_box_SECRETKEYBYTES != 32 || crypto_sign_PUBLICKEYBYTES != 32 || crypto_sign_PUBLICKEYBYTES != 32
#   error "libsodium not built correctly"
#endif
]],[[exit(0);]])],
    [
	AC_MSG_RESULT([yes])
    ],
    [
	AC_MSG_ERROR([no. please check your libsodium installation, consider re-installing])
    ]
)


# check endianess
# program returns 0 on little and 1 on big endian systems
AC_MSG_CHECKING([are we on a big endian system])
AC_RUN_IFELSE([
AC_LANG_PROGRAM([[]],[[long one= 1; exit(!(*((char *)(&one)))); ]])],
    [
	AC_MSG_RESULT([no])
	bigendian=""
    ],
    [
	AC_MSG_RESULT([yes])
	bigendian=1
    ]
)

if test -n "$bigendian"; then
    CFLAGS="$CFLAGS -D__BYTE_ORDER=__BIG_ENDIAN"
fi

AC_SUBST(PACKAGE_VERSION)

# Specify output files
AC_CONFIG_FILES([Makefile include/Makefile libpcp/Makefile src/Makefile man/Makefile tests/Makefile libpcp/libpcp1.pc])
AC_OUTPUT
