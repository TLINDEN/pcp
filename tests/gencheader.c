#include <pcp.h>

void pr(char *var, unsigned char *d, size_t len) {
  printf("size_t %s_len = %ld;\n", var, len);
  printf("unsigned char %s[%ld] = {\n", var, len);
  size_t i;
  for(i=0; i<len-1; ++i) {
    printf("0x%02x, ", (unsigned int)d[i]);
    if (i % 8 == 7) printf("\n");
  }
  printf("0x%02x\n};\n\n", (unsigned int)d[i]);
}

int main() {
  sodium_init();

  pcp_key_t *a = pcpkey_new();
  pcp_key_t *b = pcpkey_new();
  pcp_pubkey_t *p = pcpkey_pub_from_secret(b);

  unsigned char m[12] = "hallo world";

  size_t clen;
  unsigned char *c = pcp_box_encrypt(a, p, m, 12, &clen);
  unsigned char *n = ucmalloc(24);

  memcpy(n, c, 24);

  pr("secret_a", a->secret, 32);
  pr("public_a", a->pub, 32);
  pr("secret_b", b->secret, 32);
  pr("public_b", b->pub, 32);
  pr("message", m, 12);
  pr("nonce", n, 24);
  pr("cipher", &c[24], clen - 24);

  return 0;
}
