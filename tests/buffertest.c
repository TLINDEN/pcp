#include "buffertest.h"
#include <sys/mman.h>

int main() {
  /* testing basic Buffer api */
  Buffer *test = buffer_new(16, "test");
  PCPCTX *ptx = ptx_new();

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

  buffer_extract(test, g, 28, 10);
  _dump("extracted", g, 10);

  uint8_t c = buffer_last8(test);
  fprintf(stderr, "last byte: %c\n", c);

  free(g);

  buffer_free(test);

  /* testing pointer backed buffer */
  FILE *RFD;
  size_t rs;

  if((RFD = fopen("README", "rb")) == NULL) {
    fprintf(stderr, "oops, could not open README!\n");
    return 1;
  }

  fseek(RFD, 0, SEEK_END);
  rs =  ftell(RFD);
  fseek(RFD, 0, SEEK_SET);

  void *r = mmap(NULL, rs, PROT_READ, 0, fileno(RFD), 0);

  //unsigned char *r = urmalloc(256);
  Buffer *rb = buffer_new_buf("r", r, rs);

  fprintf(stderr, "r: %p rb->buf: %p\n", r, rb->buf);
  buffer_info(rb);

  size_t blocksize = 36;
  void *chunk = malloc(blocksize);

  while(buffer_done(rb) != 1) {
    if(buffer_left(rb) < blocksize)
      blocksize = buffer_left(rb);
    buffer_get_chunk(rb, chunk, blocksize);
    _dump("chunk", chunk, blocksize);
  }

  buffer_free(rb);
  free(chunk);

  _dump("r", r, rs); /* should work! */

  munmap(r, rs);
  fclose(RFD);

  fatals_ifany(ptx);
  ptx_clean(ptx);

  return 0;
}
