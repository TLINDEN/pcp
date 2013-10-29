#ifndef _HAVE_PCP_PLATFORM_H
#define _HAVE_PCP_PLATFORM_H

#if defined(CONFIG_H_FILE)
#include CONFIG_H_FILE
#elif defined(HAVE_CONFIG_H)
#include "config.h"
#else
#error Need either CONFIG_H_FILE or HAVE_CONFIG_H defined.
#endif

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else // no endian.h
# ifdef HAVE_SYS_ENDIAN_H
#   include <sys/endian.h>
#   ifdef HAVE_BETOH32
      // openbsd, use aliases
#     define be32toh betoh32
#     define htobe32 hto32be
#   endif
# else // no sys/endian.h
#   if __BYTE_ORDER == __BIG_ENDIAN
#     define be32toh(x)	((void)0)
#     define htobe32(x)	((void)0)
#   else
#     ifdef HAVE_ARPA_INET_H
#       include <arpa/inet.h>
#     else
#       ifdef HAVE_NETINET_IN_H
#         include <netinet/in.h>
#       else
#         error Need either netinet/in.h or arpa/inet.h for ntohl() and htonl()
#       endif
#     endif
#     define be32toh(x)	((u_int32_t)ntohl((u_int32_t)(x)))
#     define htobe32(x)	((u_int32_t)htonl((u_int32_t)(x)))
#   endif
#  endif // HAVE_SYS_ENDIAN_H
#endif // HAVE_ENDIAN_H


#ifndef HAVE_ARC4RANDOM_BUF
// shitty OS. we've got to use other stuff

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

static inline FILE *__getranddev() {
  FILE *R;
  if((R = fopen("/dev/urandom", "rb")) == NULL) {
    // not even this is here! what a shame
    if((R = fopen("/dev/random", "rb")) == NULL) {
      // not available or depleted. that's too bad
      fprintf(stderr, "ERROR: /dev/urandom not available, /dev/random is depleted.\n");
      fprintf(stderr, "That's horrible for you but a nightmare for me. I die. Bye.\n");
      exit(2);
    }
  }
  return R;
}

static inline u_int32_t arc4random() {
  uint32_t x;
  FILE *R = __getranddev();
  fread(&x, sizeof(uint32_t), 1, R);
  fclose(R);
  return x;
}

static inline void arc4random_buf(void *buf, size_t nbytes) {
  FILE *R = __getranddev();
  fread(buf, nbytes, 1, R);
  fclose(R);
}


#endif


#endif /* !_HAVE_PCP_PLATFORM_H */

