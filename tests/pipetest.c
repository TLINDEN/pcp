#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/select.h>

#include <pcp.h>

int main(int argc, char **argv) {
  if(argc < 3) {
    fprintf(stderr, "Usage: pipetest <read-blocksize> <d|e>\n");
    fprintf(stderr, "d - decode\ne - encode\n");
    return 1;
  }

  size_t blocksize;
  char mode;

  if((blocksize = strtol(argv[1], NULL, 0)) == 0) {
    fprintf(stderr, "Error: invalid read blocksize %s\n", argv[1]);
    return 1;
  }

  if(blocksize % 4 != 0) {
    fprintf(stderr, "Error: z85 blocksize shall be divisible by 4\n");
    return 1;
  }

  mode = argv[2][0];

  if(mode != 'd' && mode != 'e') {
    fprintf(stderr, "Error: invalid mode %s\n", argv[3]);
    return 1;
  }

  Pcpstream *in = ps_new_file(stdin);
  Pcpstream *out = ps_new_file(stdout);
  size_t got;

  if(mode == 'e')
    ps_armor(out, blocksize);
  else 
    ps_setdetermine(in, blocksize);

  void *buf = ucmalloc(blocksize);

  while(!ps_end(in)) {
    got = ps_read(in, buf, blocksize);
    if(got > 0)
      ps_write(out, buf, got);
  }

  ps_finish(out);
  ps_close(in);
  ps_close(out);

  return 0;
}
