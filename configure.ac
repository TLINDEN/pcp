# -*-sh-*-
AC_PREREQ(2.61)
AC_INIT(pcp, `cat VERSION`)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)

AC_CONFIG_HEADER(libpcp/config.h)
AM_INIT_AUTOMAKE


ORIG_CFLAGS="${CFLAGS:-none}"

# Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_SED
AC_PROG_AWK
AC_PROG_INSTALL

# Allow user to specify flags
AC_ARG_WITH([cflags],
        [  --with-cflags           Specify additional flags to pass to compiler],
        [
                if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
                    test "x${withval}" != "xyes"; then
                        CFLAGS="$CFLAGS $withval"
                fi
        ]
)

AC_ARG_WITH([ldflags],
        [  --with-ldflags          Specify additional flags to pass to linker],
        [
                if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
                    test "x${withval}" != "xyes"; then
                        LDFLAGS="$LDFLAGS $withval"
                fi
        ]
)



# Host speciffic checks
AC_CANONICAL_HOST

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(errno.h err.h stdlib.h string.h unistd.h stdio.h getopt.h\
                 limits.h stddef.h stdint.h sys/types.h sys/stat.h termios.h)

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
    umask
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


# Check for some target-specific stuff
case "$host" in
    *-*-aix*) ;;
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

# Specify output files
AC_CONFIG_FILES([Makefile libpcp/Makefile src/Makefile man/Makefile tests/Makefile])
AC_OUTPUT
