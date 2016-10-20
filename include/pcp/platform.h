/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2016 T.v.Dein.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#ifndef _HAVE_PCP_PLATFORM_H
#define _HAVE_PCP_PLATFORM_H

#include "config.h"

#ifndef HAVE_ARC4RANDOM
  #include <sodium.h>
  #define arc4random() randombytes_random()
#endif

#ifndef HAVE_ARC4RANDOM_BUF
  #include <sodium.h>
  #define arc4random_buf(buf, nbytes) randombytes((byte *)buf, nbytes)
#endif


#ifndef HAVE_ERR_H
  #include <errno.h>
  #include <string.h>
  #include <stdarg.h>
  #include <stdio.h>
  void err(int eval, const char *fmt, ...);
#else
  #include <errno.h>
  #include <err.h>
#endif



#ifndef HAVE_VASPRINTF
  #include <stdarg.h>
  int vasprintf(char **ret, const char *format, va_list args);
#endif


#ifdef _AIX_SOURCE
  #define _LINUX_SOURCE_COMPAT
#endif


#ifndef HAVE_STRNLEN
  size_t
  strnlen(const char *msg, size_t maxlen);
#endif


#ifndef HAVE_STRNSTR
  /* via FreeBSD libc */
  #include <string.h>
  char *
  strnstr(const char *s, const char *find, size_t slen);
#endif

/* size_t format string */
#ifdef __LP64__
  #define FMT_SIZE_T "llu"
  #define SIZE_T_CAST long long unsigned int
#else
  #define FMT_SIZE_T "lu"
  #define SIZE_T_CAST long unsigned int
#endif

#endif /* !_HAVE_PCP_PLATFORM_H */


