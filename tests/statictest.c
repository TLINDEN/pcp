#include <pcp.h>
#include "static.h"

int main() {
  unsigned char *t = ucmalloc(12);
  if(pcp_sodium_verify_box(&t, cipher, cipher_len, nonce, secret_b, public_a) == 0) {
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
