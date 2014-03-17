/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

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

#include "platform.h"

#ifndef HAVE_ERR_H
void err(int eval, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "pcp1");
  if (fmt != NULL) {
    fprintf(stderr, ": ");
    vfprintf(stderr, fmt, ap);
  }
  fprintf(stderr, ": %s\n", strerror(errno));
  va_end(ap);
}
#endif

#ifndef HAVE_VASPRINTF
int vasprintf(char **ret, const char *format, va_list args) {
  va_list copy;
  va_copy(copy, args);

  *ret = 0;

  int count = vsnprintf(NULL, 0, format, args);
  if (count >= 0) {
    char* buffer = (char *)malloc(count + 1);
    if (buffer != NULL) {
      count = vsnprintf(buffer, count + 1, format, copy);
      if (count < 0)
	free(buffer);
      else
	*ret = buffer;
    }
  }
  va_end(copy);  /*  Each va_start() or va_copy() needs a va_end() */

  return count;
}
#endif

#ifndef HAVE_STRNLEN
size_t
strnlen(const char *msg, size_t maxlen)
{
 size_t i;

 for (i=0; i<maxlen; i++)
 if (msg[i] == '\0')
 break;

 return i;
}
#endif


#ifndef HAVE_STRNSTR
/* via FreeBSD libc */
char *
strnstr(const char *s, const char *find, size_t slen)
{
  char c, sc;
  size_t len;
  
  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
	if (slen-- < 1 || (sc = *s++) == '\0')
	  return (NULL);
      } while (sc != c);
      if (len > slen)
	return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}
#endif
