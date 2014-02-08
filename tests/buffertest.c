#include "buffertest.h"

int main() {
  Buffer *test = buffer_new(16, "test");

  byte *a = ucmalloc(32);
  byte *b = ucmalloc(32);
  memset(a, 'A', 32);
  memset(b, 'B', 32);

  fprintf(stderr, "initial\n");
  buffer_info(test);

  int i;
  for(i=0; i<2; i++) {
    fprintf(stderr, "\nadding As\n");
    buffer_add(test, a, 32);
    buffer_info(test);
    buffer_dump(test);

    fprintf(stderr, "\nadding Bs\n");
    buffer_add(test, b, 32);
    buffer_info(test);
    buffer_dump(test);
  }

  free(a);
  free(b);


  size_t x;
  size_t bs = buffer_size(test);
  void *g = ucmalloc(32);
  for(x=0; x < bs; x+=32) {
    fprintf(stderr, "before get\n");
    buffer_info(test);
    if(buffer_get_chunk(test, g, 32) > 0) {
    fprintf(stderr, "after get\n");
      buffer_info(test);
      _dump("got", g, 32);
    }
    fprintf(stderr, "\n");
  }

  buffer_extract(test, g, 28, 38);
  _dump("extracted", g, 10);

  uint8_t c = buffer_last8(test);
  fprintf(stderr, "last byte: %c\n", c);

  free(g);

  buffer_free(test);

  fatals_ifany();

  return 0;
}
