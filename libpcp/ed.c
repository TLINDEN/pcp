/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/

#include "ed.h"

unsigned char * pcp_ed_verify(unsigned char *signature, size_t siglen, pcp_pubkey_t *p) {
  unsigned char *message = ucmalloc(siglen - crypto_sign_BYTES);
  size_t mlen;

  if(crypto_sign_open(message, &mlen, signature, siglen, p->edpub) != 0) {
    fatal("Failed to open the signature using the public key 0x%s!\n", p->id);
    goto errve1;
  }

  return message;

 errve1:
  free(message);
  return NULL;
}

unsigned char *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s) {
  size_t mlen = messagesize + crypto_sign_BYTES;
  unsigned char *signature = ucmalloc(mlen);

  crypto_sign(signature, &mlen, message, messagesize, s->edsecret);

  return signature;
}

size_t pcp_ed_sign_buffered(FILE *in, FILE *out, pcp_key_t *s, int z85) {
  unsigned char in_buf[PCP_BLOCK_SIZE];
  size_t cur_bufsize = 0;
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char hash[crypto_generichash_BYTES_MAX];

  crypto_generichash_init(st, NULL, 0, 0);

  if(z85)
    fprintf(out, "%s\nHash: Blake2\n\n", PCP_SIG_HEADER);

  while(!feof(in)) {
    cur_bufsize = fread(&in_buf, 1, PCP_BLOCK_SIZE, in);
    if(cur_bufsize <= 0)
      break;

    crypto_generichash_update(st, in_buf, cur_bufsize);
    fwrite(in_buf, cur_bufsize, 1, out);
  }

  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    free(st);
    return 0;
  }

  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  size_t mlen = + crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  unsigned char *signature = ucmalloc(mlen);
  crypto_sign(signature, &mlen, hash, crypto_generichash_BYTES_MAX, s->edsecret);

  if(z85) {
    fprintf(out, "\n%s\nVersion: PCP v%d.%d.%d\n\n", PCP_SIG_START, PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH);
    size_t zlen;
    char *z85encoded = pcp_z85_encode((unsigned char*)signature, crypto_sign_BYTES, &zlen);
    fprintf(out, "%s\n%s\n", z85encoded, PCP_SIG_END);
  }
  else {
    fwrite(signature, crypto_sign_BYTES, 1, out);
  }

  if(fileno(in) != 0)
    fclose(in);
  if(fileno(out) != 1)
    fclose(out);

  free(st);

  return mlen; // ???
}


unsigned char *pcp_ed_verify_buffered(FILE *in, pcp_pubkey_t *p) {
  unsigned char in_buf[PCP_BLOCK_SIZE];
  size_t cur_bufsize = 0;
  int z85 = 0;
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char hash[crypto_generichash_BYTES_MAX];
  char *zhead;
  size_t hlen = strlen(PCP_SIG_HEADER);
  size_t nextsize = 0;
  size_t restsize = 0;
  size_t mlen = + crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  unsigned char z85encoded[181];
  unsigned char sighash[mlen];
  unsigned char sig[crypto_sign_BYTES];
  char z85sigstart[] = PCP_SIG_START;
  char binsigstart[] = PCP_SIGPREFIX;
  int offset = -1;

  crypto_generichash_init(st, NULL, 0, 0);

  // determine sig type, clear or bin
  cur_bufsize = hlen + 14; // header + hash name + 3x newline
  fread(&in_buf, 1, cur_bufsize, in);
  zhead = ucmalloc(cur_bufsize);
  memcpy(zhead, in_buf, hlen);
  memset(&zhead[hlen], 0, 1);

  if(strncmp(zhead, PCP_SIG_HEADER, hlen) == 0)
    z85 = 1;
  else
    nextsize = cur_bufsize;
  
  while(!feof(in)) {
    if(z85 == 0 && nextsize > 0) {
      // bin sig, read blocksize - header and put zheader in front of it again
      cur_bufsize = fread(&in_buf[hlen], 1, PCP_BLOCK_SIZE - hlen, in);
      memcpy(in_buf, zhead, hlen);
      cur_bufsize += hlen;
    }
    else
      cur_bufsize = fread(&in_buf, 1, PCP_BLOCK_SIZE, in);

    if(cur_bufsize <= 0)
      break;

    if(z85) {
      // look if we need to cut something from the current block
      offset = _findoffset(in_buf, cur_bufsize, z85sigstart, strlen(z85sigstart));
      if(offset > 0) {
	// we need to cut
	restsize = cur_bufsize - offset; // the start of the armor sig
	cur_bufsize -= restsize; // bin stuff in front of it, if any
	memcpy(z85encoded, &in_buf[offset], restsize); // save the armor sig chunk
      }
    }
    else {
      // do the same for the bin sig
      offset = _findoffset(in_buf, cur_bufsize, binsigstart, strlen(binsigstart));
      if(offset > 0) {
	// we need to cut
	restsize = cur_bufsize - offset + strlen(binsigstart); // the start of the bin sig
	cur_bufsize -= offset; // bin stuff in front of it, if any
	memcpy(sighash, &in_buf[offset + strlen(binsigstart)], restsize); // save the armor sig chunk
      }
    }

    if(offset == -1)
      crypto_generichash_update(st, in_buf, cur_bufsize);
  }

  if(offset == -1) {
    fatal("Error, the signature doesn't contain the ed25519 signed hash\n");
    goto errvb1;
  }

  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  // pull in the remainder
  cur_bufsize = fread(&in_buf, 1, restsize, in);

  // put hashsig together
  if(z85) {
    memcpy(&z85encoded[restsize], in_buf, cur_bufsize);
    char *z85block = pcp_readz85string(z85encoded, restsize + cur_bufsize);
    if(z85block == NULL)
      goto errvb1;
    size_t dstlen;
    unsigned char *z85decoded = pcp_z85_decode(z85block, &dstlen);
    if(dstlen != mlen) {
      fatal("z85 decoded signature didn't result in a proper signed hash\n");
      goto errvb1;
    }
    memcpy(sighash, z85decoded, mlen);
  }
  else {
    memcpy(&sighash[restsize], in_buf, cur_bufsize); // FIXME: check if cur_bufsize holds enough
  }

  // huh, how did we made it til here?
  unsigned char *verifiedhash = NULL;
  if(p == NULL) {
    pcphash_iteratepub(p) {
      verifiedhash = pcp_ed_verify(sighash, mlen, p);
      if(verifiedhash != NULL)
	break;
    }
  }
  else {
    verifiedhash = pcp_ed_verify(sighash, mlen, p);
  }

  if(verifiedhash == NULL)
    goto errvb1;

 
  if(memcmp(verifiedhash, hash, crypto_generichash_BYTES_MAX) != 0) {
    // sig verified, but the hash doesn't
    fatal("signed hash doesn't match with actual hash of signed file content\n");
    free(verifiedhash);
  }

  return verifiedhash;
  

 errvb1:
  free(st);
  free(zhead);
  return NULL;
}

