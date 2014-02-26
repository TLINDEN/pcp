#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <pcp.h>

int main(int argc, char **argv) {
  if(argc < 4) {
    fprintf(stderr, "Usage: pipetest <read-blocksize> <z85-blocksize> <d|e>\n");
    fprintf(stderr, "d - decode\ne - encode\n");
    return 1;
  }

  size_t rblocksize;
  size_t zblocksize;
  char mode;

  if((rblocksize = strtol(argv[1], NULL, 0)) == 0) {
    fprintf(stderr, "Error: invalid read blocksize %s\n", argv[1]);
    return 1;
  }

  if((zblocksize = strtol(argv[2], NULL, 0)) == 0) {
    fprintf(stderr, "Error: invalid z85 blocksize %s\n", argv[2]);
    return 1;
  }

  if(zblocksize % 4 != 0) {
    fprintf(stderr, "Error: z85 blocksize shall be divisible by 4\n");
    return 1;
  }

  mode = argv[3][0];

  if(mode != 'd' && mode != 'e') {
    fprintf(stderr, "Error: invalid mode %s\n", argv[3]);
    return 1;
  }

  Pcpstream *in = ps_new_file(stdin);
  Pcpstream *out = ps_new_file(stdout);
  size_t got;

  if(mode == 'e')
    ps_armor(out, zblocksize);
  else 
    ps_setdetermine(in, zblocksize);

  void *buf = ucmalloc(rblocksize);

  while(!ps_end(in)) {
    got = ps_read(in, buf, rblocksize);
    if(got > 0)
      ps_write(out, buf, got);
  }

  ps_finish(out);
  ps_close(in);
  ps_close(out);

  return 0;
}
