#include "z85util.h"

int pcpz85_encode(char *infile, char *outfile) {
  FILE *in;
  FILE *out;

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto errz1;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto errz1;
    }
  }

  unsigned char *input = NULL;
  size_t inputBufSize = 0;
  unsigned char byte[1];
  
  while(!feof(in)) {
    if(!fread(&byte, 1, 1, in))
      break;
    unsigned char *tmp = realloc(input, inputBufSize + 1);
    input = tmp;
    memmove(&input[inputBufSize], byte, 1);
    inputBufSize ++;
  }
  fclose(in);

  if(inputBufSize == 0) {
    fatal("Input file is empty!\n");
    goto errz2;
  }

  size_t zlen;
  char *encoded = pcp_z85_encode(input, inputBufSize, &zlen);

  if(encoded != NULL) {
    fprintf(out, "%s\n%s\n%s\n", PCP_ZFILE_HEADER, encoded, PCP_ZFILE_FOOTER);
    if(ferror(out) != 0) {
      fatal("Failed to write z85 output!\n");
    }
    free(encoded);
    goto errz2;
  }

  return 0;

 errz2:
  free(input);

 errz1:
  return 1;
}




int pcpz85_decode(char *infile, char *outfile) {
  FILE *in;
  FILE *out;

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto errdz1;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto errdz1;
    }
  }

  char *encoded = pcp_readz85file(in);

  if(encoded == NULL)
    goto errdz1;

  size_t clen;
  unsigned char *decoded = pcp_z85_decode(encoded, &clen);

  if(decoded == NULL)
    goto errdz2;
  
  fwrite(decoded, clen, 1, out);
  fclose(out);
  if(ferror(out) != 0) {
    fatal("Failed to write decoded output!\n");
    goto errdz3;
  }

  free(decoded);
  return 0;

 errdz3:
  free(decoded);

 errdz2:
  free(encoded);

 errdz1:
  return 1;
}
