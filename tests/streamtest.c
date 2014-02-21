#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <pcp.h>

int main() {
  /* create a file with "encrypted" data */
  FILE *out, *in;
  unsigned char clear[8] = "ABCDEFGH";
  unsigned char key[8]   = "IxD8Lq1K";
  unsigned char crypt[11] = {0};
  int blocks = 24;
  int i = 0;

  if((out = fopen("teststream.out", "wb+")) == NULL) {
    fprintf(stderr, "oops, could not open file!\n");
    return 1;
  }
  Pcpstream *pout = ps_new_file(out);
  ps_armor(pout);

  /* "encrypt" a couple of times into the file */
  for(i=0; i<blocks; i++) {
    memcpy(crypt, clear, 8);
    _xorbuf(key, crypt, 8);
    ps_write(pout, crypt, 8);
  }
  ps_close(pout);
  fclose(out);

  /* read it in again using an in and an out stream */
  if((in = fopen("teststream.out", "rb")) == NULL) {
    fprintf(stderr, "oops, could not open file!\n");
    return 1;
  }
  Pcpstream *pin = ps_new_file(in);
  ps_determine(pin);

  /* we'll use this stream to put the "decrypted" data in.
     note, that this could be a file as well.  */
  Pcpstream *pclear = ps_new_outbuffer();

  /* read and "decrypt" */
  for(i=0; i<blocks; i++) {
    ps_read(pin, crypt, 10);
    _xorbuf(key, crypt, 8);
    ps_write(pclear, crypt, 8);
  }
  ps_close(pin);
  fclose(in);

  /* now extract the buffer from the output stream */
  Buffer *result = ps_buffer(pclear);

  /* and verify if it's "decrypted" (re-use crypt) */
  for(i=0; i<blocks; i++) {
    buffer_get_chunk(result, crypt, 8);
    _dump("chunk", crypt, 8);
    if(memcmp(crypt, clear, 8) != 0) {
      fprintf(stderr, "Oops, block %d doesn't match\n", i);
      goto error;
    }
  }

  ps_close(pclear);

  fprintf(stderr, "done\n");

  return 0;

 error:
  ps_close(pclear);
  return 1;
}
