#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <pcp.h>

#define TRUE 1
#define FALSE 0

static const char *tell[] = {
  NULL,
  "Headers: no,  Newlines: yes, Compliant: yes",
  "Headers: no,  Newlines: no,  Compliant: yes",
  "Headers: no,  Newlines: yes, Compliant: yes - no begin header",
  "Headers: yes, Newlines: yes, Compliant: no - empty comment",
  "Headers: yes, Newlines: yes, Compliant: no - missing z85 char",
};

int main(int argc, char **argv) {
  int ret;
  size_t clearlen = 256;
  size_t zlen;
  char *z85;
  PCPCTX *ptx = ptx_new();

  if(argc < 2) {
    fprintf(stderr, "Usage: decodertest <N>\n");
    return 1;
  }

  int mode;
  if((mode = strtol(argv[1], NULL, 0)) == 0) {
    fprintf(stderr, "Error: decoder sub number %s\n", argv[1]);
    return 1;
  }

  byte *clear = urmalloc(256);

  /* encode it */
  z85 = pcp_z85_encode(clear, clearlen, &zlen, 0);
  zlen -= 1;

  if(z85 == NULL) {
    ret = FALSE;
    if(ptx->pcp_errset == 0) {
      fatal(ptx, "failed to encode data to Z85\n");
    }
    goto OUT;
  }

  Buffer *Z = buffer_new(384, "z85");
  buffer_add(Z, z85, zlen);
  size_t z = buffer_size(Z);
  size_t i;
  uint8_t c;

  Pcpstream *out = ps_new_outbuffer();

  /*
    modi:                           expect
    1 = no headers incl newlines    ok
    2 = no headers no newlines      ok
    3 = no begin header             ok
    4 = headers, empty comment      fail
    5 = headers, missing z char     fail
  */

  /* begin header */
  if(mode > 3) {
    ps_print(out, "%s\r\n", PCP_ZFILE_HEADER);
  }

  /* empty comment */
  if(mode == 4) {
    ps_print(out, "Version:\r\n");
  }

  /* z85 output */
  if(mode == 5) {
    z--;
  }
  int l=0;
  for (i=0; i<z; ++i) {
    if(mode != 2 && l % 64 == 63 && l > 0) {
      ps_print(out, "\r\n");
      l = 0;
    }
    c = buffer_get8(Z);
    ps_write(out, &c, 1);
    l++;
  }

  /* footer */
  if(mode > 2) {
    ps_print(out, "\r\n%s\r\n", PCP_ZFILE_FOOTER);
  }

  /* done creating z85 file */
  Buffer *zdone = ps_buffer(out);
  byte *back = NULL;

  /* control output */
  
  fprintf(stderr, "%s:\n\n%s\n", tell[mode], buffer_get_str(zdone));

  /* line decoder */

  char *raw = pcp_readz85string(ptx, buffer_get(zdone), buffer_size(zdone));

  if(raw == NULL) {
    /* unexpected */
    ret = FALSE;
  }
  else {
    back = pcp_z85_decode(ptx, raw, &zlen);
    if(back == NULL) {
      if(mode > 3) {
	/* expected fail */
	ret = TRUE;
      }
      else {
	/* expected ok */
	ret = FALSE;
      }
    }
    else {
      if(mode > 3) {
	/* expected fail */
	ret = FALSE;
      }
      else {
	/* expected ok */
	ret = TRUE;
      }
    }
  }

  /* finally see if content matches */
  if(back != NULL) {
    if(mode <= 3 && memcmp(back, clear, 256) != 0) {
      ret = FALSE;
      if(ptx->pcp_errset == 0) {
	fatal(ptx, "decoded content doesn't match\n");
      }
    }
  }

  /* finish */
  ps_close(out);
  buffer_free(Z);
  if(raw != NULL)
    free(raw);
  if(z85 != NULL)
    free(z85);

 OUT:
  if(ret == TRUE) {
    fprintf(stdout, "%d - ok\n", mode);
  }
  else {
    fprintf(stdout, "%d - failed\n", mode);
    fatals_ifany(ptx);
  }

  ptx_clean(ptx);

  return ret;
}
