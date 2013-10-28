#ifndef _HAVE_PCP_WARN_H
#define _HAVE_PCP_WARN_H

#ifdef HAVE_ERR_H
#include <err.h>
#else
#define NEED_WARN_PROGNAME
const char * warn_progname;
void warn(const char *, ...);
void warnx(const char *, ...);
#endif

#endif /* !_HAVE_WARN_H */
