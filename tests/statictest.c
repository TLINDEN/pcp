#include <pcp.h>
#include "static.h"

int main() {
  if(sodium_init() == -1) return 1;
  unsigned char *t = ucmalloc(12);
  if(crypto_box_open_easy(t, cipher, cipher_len, nonce, public_a, secret_b) == 0) {
    if(memcmp(t, message, message_len) == 0) {
      printf("ok\n");
    }
    else {
      printf("decrypted but message doesnt match\n");
      return 1;
    }
  }
  else {
    printf("failed to decrypt\n");
    return 1;
  }
  return 0;
}
