#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <limits.h>

#include "mem.h"
#include "defines.h"
#include "keyprint.h"
#include "key.h"

struct _pw_t {
  char hash[65];
  UT_hash_handle hh;
};
typedef struct _pw_t pw;

int main() {
  int i, t, p;
  char *pass = ucmalloc(4);
  unsigned char *h;
  char tmp[65];
  pw *item;
  pw *list = NULL;
  pw *have = NULL;
  unsigned char nonce[32] = {1};

  if(sodium_init() == -1) return 1;

  for(i=97; i<126; ++i) {
    pass[0] = i;
    pass[1] = 0;
    h = pcp_derivekey(pass, nonce);

    p =0;
    for(t=0; t<32; ++t) {
      sprintf(&tmp[p], "%02x", h[t]);
      p += 2;
    }

    have = NULL;
    HASH_FIND_STR(list, tmp, have);
    if(have == NULL) {
      item = ucmalloc(sizeof(pw));
      memcpy(item->hash, tmp, 65);
      HASH_ADD_STR( list, hash, item ); 
    }
    else {
      fprintf(stderr, "Error: collision found: %s!\n", have->hash);
      return 1;
    }
  }

  fprintf(stderr, "ok\n");
  return 0;
}
