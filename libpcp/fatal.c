#include "defines.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fatal(const char * fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  
  vasprintf(&PCP_ERR, fmt, ap);

  va_end(ap);

  PCP_ERRSET = 1;
}

void fatals_reset() {
  PCP_ERRSET = 0;
}

void fatals_ifany() {
  if(PCP_ERRSET == 1) {
    fprintf(stderr, PCP_ERR);
    if(errno) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
    }
    free(PCP_ERR);
    PCP_EXIT = 1;
  }
}
