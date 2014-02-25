/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

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

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#include "crypto.h"

size_t pcp_sodium_box(byte **cipher,
		      byte *cleartext,
		      size_t clearsize,
		      byte *nonce,
		      byte *secret,
		      byte *pub) {

  byte *pad_clear;
  byte *pad_cipher;

  size_t ciphersize = (clearsize + crypto_box_ZEROBYTES) - crypto_box_BOXZEROBYTES;

  pad_cipher = ucmalloc(crypto_box_ZEROBYTES + clearsize);
  pcp_pad_prepend(&pad_clear, cleartext, crypto_box_ZEROBYTES, clearsize);
  
  /*  crypto_box(c,m,mlen,n,pk,sk); */
  crypto_box(pad_cipher, pad_clear,
	     clearsize + crypto_box_ZEROBYTES, nonce, pub, secret);

  pcp_pad_remove(cipher, pad_cipher, crypto_secretbox_BOXZEROBYTES, ciphersize);

  free(pad_clear);
  free(pad_cipher);

  return ciphersize;
}




int pcp_sodium_verify_box(byte **cleartext, byte* message,
			  size_t messagesize, byte *nonce,
			  byte *secret, byte *pub) {
  /*  verify/decrypt the box */
  byte *pad_cipher;
  byte *pad_clear;
  int success = -1;

  pcp_pad_prepend(&pad_cipher, message, crypto_box_BOXZEROBYTES, messagesize);
  pad_clear = (byte *)ucmalloc((crypto_box_ZEROBYTES+ messagesize));

  /*  crypto_box_open(m,c,clen,n,pk,sk); */
  if (crypto_box_open(pad_clear, pad_cipher,
		      messagesize + crypto_box_BOXZEROBYTES,
		      nonce, pub, secret) == 0) {
    success = 0;
  }

  pcp_pad_remove(cleartext, pad_clear, crypto_box_ZEROBYTES, messagesize);

  free(pad_clear);
  free(pad_cipher);

  return success;
}




byte *pcp_box_encrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
			       byte *message, size_t messagesize,
			       size_t *csize) {

  byte *nonce = pcp_gennonce();

  byte *cipher;

  size_t es = pcp_sodium_box(&cipher, message, messagesize, nonce,
		 secret->secret, pub->pub);

  if(es <= messagesize) {
    fatal("failed to encrypt message!\n");
    goto errbec;
  }

  /*  scip */
  /* fprintf(stderr, "public: "); pcpprint_bin(stderr, pub->pub, 32); fprintf(stderr, "\n"); */
  /* fprintf(stderr, "secret: "); pcpprint_bin(stderr, secret->secret, 32); fprintf(stderr, "\n"); */
  /* fprintf(stderr, "cipher: "); pcpprint_bin(stderr, cipher, es); fprintf(stderr, "\n"); */
  /* fprintf(stderr, " nonce: "); pcpprint_bin(stderr, nonce, crypto_secretbox_NONCEBYTES); fprintf(stderr, "\n"); */

  /*  put nonce and cipher together */
  byte *combined = ucmalloc(es + crypto_secretbox_NONCEBYTES);
  memcpy(combined, nonce, crypto_secretbox_NONCEBYTES);
  memcpy(&combined[crypto_secretbox_NONCEBYTES], cipher, es);

  free(cipher);
  free(nonce);

  *csize = es + crypto_secretbox_NONCEBYTES;

  return combined;

 errbec:
  if(cipher != NULL)
    free(cipher);
  free(nonce);

  return NULL;
}


byte *pcp_box_decrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
			       byte *cipher, size_t ciphersize,
			       size_t *dsize) {

  byte *message = NULL;

  byte *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  byte *cipheronly = ucmalloc(ciphersize - crypto_secretbox_NONCEBYTES);

  memcpy(nonce, cipher, crypto_secretbox_NONCEBYTES);
  memcpy(cipheronly, &cipher[crypto_secretbox_NONCEBYTES],
	 ciphersize - crypto_secretbox_NONCEBYTES);

  if(pcp_sodium_verify_box(&message, cipheronly,
			   ciphersize - crypto_secretbox_NONCEBYTES,
			   nonce, secret->secret, pub->pub) != 0){
    fatal("failed to decrypt message!\n");
    goto errbed;
  }

  free(nonce);
  free(cipheronly);

  /*  resulting size: */
  /*  ciphersize - crypto_secretbox_ZEROBYTES */
  *dsize = ciphersize - crypto_secretbox_NONCEBYTES - PCP_CRYPTO_ADD;
  return message;

 errbed:
  free(nonce);
  free(cipheronly);
  if(message != NULL)
    free(message);

  return NULL;
}

size_t pcp_decrypt_stream(Pcpstream *in, Pcpstream* out, pcp_key_t *s, byte *symkey, int verify) {
  pcp_pubkey_t *cur = NULL;
  pcp_pubkey_t *sender = NULL;
  byte *reccipher = NULL;
  int recmatch, self;
  uint32_t lenrec;
  byte head[1];
  size_t cur_bufsize, rec_size, nrec;
  
  byte rec_buf[PCP_ASYM_RECIPIENT_SIZE];

#ifdef PCP_ASYM_ADD_SENDER_PUB
  byte *senderpub;
#endif

  nrec = recmatch = self = 0;

  if(ps_tell(in) == 1) {
    /*  header has already been determined outside the lib */
    if(symkey != NULL)
      self = 1;
  }
  else {
    /*  step 1, check header */
    cur_bufsize = ps_read(in, head, 1); /* fread(head, 1, 1, in); */
    if(cur_bufsize != 1 && !ps_end(in) && !ps_err(in)) {
      if(head[0] == PCP_SYM_CIPHER) {
	if(symkey != NULL)
	  self = 1;
	else {
	  fatal("Input is symetrically encrypted but no key have been specified (lib usage failure)\n");
	  goto errdef1;
	}
      }
      else if(head[0] == PCP_ASYM_CIPHER) {
	self = 0;
      }
    }
  }

  if(self) {
    /*  just decrypt symetrically and go outa here */
    return pcp_decrypt_stream_sym(in, out, symkey, NULL);
  }

#ifdef PCP_ASYM_ADD_SENDER_PUB
  /*  step 2, sender's pubkey */
  cur_bufsize = ps_read(in, &in_buf, crypto_box_PUBLICKEYBYTES); /* fread(&in_buf, 1, crypto_box_PUBLICKEYBYTES, in); */
  if(cur_bufsize !=  crypto_box_PUBLICKEYBYTES && !ps_end(in) && !ps_err(in)) {
    fatal("Error: input file doesn't contain senders public key\n");
    goto errdef1;
  }
#endif

  /*  step 3, check len recipients */
  cur_bufsize = ps_read(in, &lenrec, 4); /* fread(&lenrec, 1, 4, in); */
  if(cur_bufsize != 4 && !ps_end(in) && !ps_err(in)) {
    fatal("Error: input file doesn't contain recipient count\n");
    goto errdef1;
  }
  lenrec = be32toh(lenrec);
  
  if(verify) {
    reccipher = ucmalloc(lenrec * PCP_ASYM_RECIPIENT_SIZE);
  }



  /*  step 4, fetch recipient list and try to decrypt it for us */
  for(nrec=0; nrec<lenrec; nrec++) {
    cur_bufsize = ps_read(in, &rec_buf, PCP_ASYM_RECIPIENT_SIZE); /* fread(&rec_buf, 1, PCP_ASYM_RECIPIENT_SIZE, in); */
    if(cur_bufsize != PCP_ASYM_RECIPIENT_SIZE && !ps_end(in) && !ps_err(in)) {
      fatal("Error: input file corrupted, incomplete or no recipients\n");
      goto errdef1;
    }
    recmatch = 0;

    pcphash_iteratepub(cur) {
      byte *recipient;
      recipient = pcp_box_decrypt(s, cur, rec_buf, PCP_ASYM_RECIPIENT_SIZE, &rec_size);
      if(recipient != NULL && rec_size == crypto_secretbox_KEYBYTES) {
	/*  found a match */
	recmatch = 1;
	sender = cur;
	symkey = ucmalloc(crypto_secretbox_KEYBYTES);
	memcpy(symkey, recipient, crypto_secretbox_KEYBYTES);
	free(recipient);
	break;
      }
    }
    if(verify) {
      size_t R = nrec * (PCP_ASYM_RECIPIENT_SIZE);
      memcpy(&reccipher[R], rec_buf, PCP_ASYM_RECIPIENT_SIZE);
    }
  }
  

  if(recmatch == 0) {
    fatal("Sorry, there's no matching public key in your vault for decryption\n");
    goto errdef1;
  }
  
  
  /*  step 5, actually decrypt the file, finally */
  if(verify) {
    pcp_rec_t *rec = pcp_rec_new(reccipher, nrec * PCP_ASYM_RECIPIENT_SIZE, NULL, cur);
    return pcp_decrypt_stream_sym(in, out, symkey, rec);
    pcp_rec_free(rec);
  }
  else
    return pcp_decrypt_stream_sym(in, out, symkey, NULL);


 errdef1:
  return 0;
}

size_t pcp_encrypt_stream(Pcpstream *in, Pcpstream *out, pcp_key_t *s, pcp_pubkey_t *p, int sign) {
  byte *symkey;
  int recipient_count;
  byte *recipients_cipher;
  pcp_pubkey_t *cur, *t;
  size_t es;
  int nrec;
  uint32_t lenrec;
  size_t rec_size, out_size;
  byte head[1];
  byte rs[1];

  /*
      6[1]|temp_keypair.pubkey|len(recipients)[4]|(recipients...)|(secretboxes...)
    where recipients is a concatenated list of
      random_nonce|box(temp_keypair.privkey, recipient crypto pk, random_nonce, packet key)
  */

  /*  preparation */
  /*  A, generate sym key */
  symkey = urmalloc(crypto_secretbox_KEYBYTES);

  /*  B, encrypt it asymetrically for each recipient */
  recipient_count = HASH_COUNT(p);
  rec_size = PCP_ASYM_RECIPIENT_SIZE;
  rs[0] = PCP_ASYM_RECIPIENT_SIZE - crypto_secretbox_NONCEBYTES;
  recipients_cipher = ucmalloc(rec_size * recipient_count);
  nrec = 0;

  HASH_ITER(hh, p, cur, t) {
    byte *rec_cipher;
    rec_cipher = pcp_box_encrypt(s, cur, symkey, crypto_secretbox_KEYBYTES, &es);
    if(es != rec_size) {
      fatal("invalid rec_size, expected %dl, got %dl\n", rec_size, es);
      if(rec_cipher != NULL)
	free(rec_cipher);
      goto errec1;
    }

    /* put it into the recipient list, already includes the nonce */
    memcpy(&recipients_cipher[nrec * rec_size], rec_cipher, rec_size);    
    nrec++;
    free(rec_cipher);
  }

  /*  step 1, file header */
  head[0] = PCP_ASYM_CIPHER;
  ps_write(out, head, 1);
  /* fwrite(head, 1, 1, out); */
  /* fprintf(stderr, "D: header - 1\n"); */
  if(ps_err(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    goto errec1;
  }

#ifdef PCP_ASYM_ADD_SENDER_PUB
  /*  step 2, sender's pubkey */
  ps_write(out, s->pub, crypto_box_PUBLICKEYBYTES);
  /*fwrite(s->pub, crypto_box_PUBLICKEYBYTES, 1, out); */
  /* fprintf(stderr, "D: sender pub - %d\n", crypto_box_PUBLICKEYBYTES); */
  if(ps_err(out) != 0)
    goto errec1;
#endif

  /*  step 3, len recipients, big endian */
  lenrec = recipient_count;
  lenrec = htobe32(lenrec);
  ps_write(out, &lenrec, 4);
  /* fwrite(&lenrec, 4, 1, out); */
  /* fprintf(stderr, "D: %d recipients - 4\n", recipient_count); */
  if(ps_err(out) != 0)
    goto errec1;

  /*  step 4, recipient list */
  ps_write(out, recipients_cipher, rec_size * recipient_count);
  /* fwrite(recipients_cipher, rec_size * recipient_count, 1, out); */
  /* fprintf(stderr, "D: recipients - %ld * %d\n",  rec_size, recipient_count); */
  if(ps_err(out) != 0)
    goto errec1;

  out_size = 5 + (rec_size * recipient_count) + crypto_box_PUBLICKEYBYTES;

  /*  step 5, actual encrypted data */
  size_t sym_size = 0;
  if(sign) {
    pcp_rec_t *rec = pcp_rec_new(recipients_cipher, rec_size * recipient_count, s, NULL);
    sym_size = pcp_encrypt_stream_sym(in, out, symkey, 1, rec);
    pcp_rec_free(rec);
  }
  else
    sym_size = pcp_encrypt_stream_sym(in, out, symkey, 1, NULL);

  if(sym_size == 0)
    goto errec1;


  return out_size + sym_size;

  

 errec1:
  memset(symkey, 0, crypto_secretbox_KEYBYTES);
  free(symkey);
  free(recipients_cipher);

  return 0;
}




size_t pcp_encrypt_stream_sym(Pcpstream *in, Pcpstream *out, byte *symkey, int havehead, pcp_rec_t *recsign) {
  /*
    havehead = 0: write the whole thing from here
    havehead = 1: no header, being called from asym...
  */

  byte *buf_nonce;
  byte *buf_cipher;
  byte in_buf[PCP_BLOCK_SIZE];
  size_t cur_bufsize = 0;
  size_t out_size = 0;
  size_t es;
  crypto_generichash_state *st = NULL;
  byte *hash = NULL;
  byte head[1];

  if(recsign != NULL) {
    st = ucmalloc(sizeof(crypto_generichash_state));
    hash = ucmalloc(crypto_generichash_BYTES_MAX);
    crypto_generichash_init(st, NULL, 0, 0);
  }

  if(havehead == 0) {
    head[0] = PCP_SYM_CIPHER;
    es = ps_write(out, head, 1);
    /* es = fwrite(head, 1, 1, out); */
    if(ps_err(out) != 0) {
      fatal("Failed to write encrypted output!\n");
      return 0;
    }
  }

#ifdef PCP_CBC
  /*  write the IV, pad it with rubbish, since pcp_decrypt_file_sym */
  /*  reads in with  PCP_BLOCK_SIZE_IN buffersize and uses the last */
  /*  PCP_BLOCK_SIZE as IV. */
  byte *iv = urmalloc(PCP_BLOCK_SIZE);
  byte *ivpad = urmalloc(PCP_BLOCK_SIZE_IN - PCP_BLOCK_SIZE);

  ps_write(out, ivpad, PCP_BLOCK_SIZE_IN - PCP_BLOCK_SIZE);
  ps_write(out, iv, PCP_BLOCK_SIZE);
  /*
  fwrite(ivpad, PCP_BLOCK_SIZE_IN - PCP_BLOCK_SIZE, 1, out);
  fwrite(iv, PCP_BLOCK_SIZE, 1, out);*/
#endif

  /*  32k-ECB-mode. FIXME: maybe support CBC as well or only use CBC? */
  while(!ps_end(in)) {
    cur_bufsize = ps_read(in, &in_buf, PCP_BLOCK_SIZE); /* fread(&in_buf, 1, PCP_BLOCK_SIZE, in); */
    if(cur_bufsize <= 0)
      break;
    buf_nonce = pcp_gennonce();

#ifdef PCP_CBC
    /*  apply IV to current clear */
    _xorbuf(iv, in_buf, cur_bufsize);
#endif

    es = pcp_sodium_mac(&buf_cipher, in_buf, cur_bufsize, buf_nonce, symkey);

    ps_write(out, buf_nonce, crypto_secretbox_NONCEBYTES);
    ps_write(out, buf_cipher, es);

    /*
    fwrite(buf_nonce, crypto_secretbox_NONCEBYTES, 1, out);
    fwrite(buf_cipher, es, 1, out); */
    free(buf_nonce);
    free(buf_cipher);
    out_size += crypto_secretbox_NONCEBYTES + es;

    if(recsign != NULL)
      crypto_generichash_update(st, in_buf, cur_bufsize);

#ifdef PCP_CBC
    /*  make current cipher to next IV, ignore nonce and pad */
    memcpy(iv, &buf_cipher[PCP_CRYPTO_ADD], PCP_BLOCK_SIZE);
#endif
  }

  if(ps_err(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    goto errsym1;
  }

  if(recsign != NULL) {
    /* add encrypted recipient list to the hash */
    crypto_generichash_update(st, recsign->cipher, recsign->ciphersize);
    crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

    /* generate the actual signature */
    byte *signature = pcp_ed_sign(hash, crypto_generichash_BYTES_MAX, recsign->secret);
    size_t siglen = crypto_sign_BYTES + crypto_generichash_BYTES_MAX;

    /* encrypt it as well */
    buf_nonce = pcp_gennonce();
    es = pcp_sodium_mac(&buf_cipher, signature, siglen, buf_nonce, symkey);

    ps_write(out, buf_nonce, crypto_secretbox_NONCEBYTES);
    ps_write(out, buf_cipher, es);
    /*
    fwrite(buf_nonce, crypto_secretbox_NONCEBYTES, 1, out);
    fwrite(buf_cipher, es, 1, out); */

    free(st);
    free(signature);
    free(hash);
  }

  return out_size;

 errsym1:
  if(symkey != NULL) {
    free(st);
    free(hash);
  }
  return 0;
}

size_t pcp_decrypt_stream_sym(Pcpstream *in, Pcpstream* out, byte *symkey, pcp_rec_t *recverify) {
  byte *buf_nonce;
  byte *buf_cipher;
  byte *buf_clear;
  size_t out_size, cur_bufsize, es;
  size_t ciphersize = (PCP_BLOCK_SIZE_IN) - crypto_secretbox_NONCEBYTES;
  byte in_buf[PCP_BLOCK_SIZE_IN];

  buf_nonce  = ucmalloc(crypto_secretbox_NONCEBYTES);
  buf_cipher = ucmalloc(ciphersize);
  out_size = 0;

  byte *signature = NULL;
  byte *signature_cr = NULL;
  size_t siglen = crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  size_t siglen_cr = siglen + PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES;
  crypto_generichash_state *st = NULL;
  byte *hash = NULL;

  if(recverify != NULL) {
    st = ucmalloc(sizeof(crypto_generichash_state));
    hash = ucmalloc(crypto_generichash_BYTES_MAX);
    crypto_generichash_init(st, NULL, 0, 0);
    signature_cr = ucmalloc(siglen_cr);
  }

#ifdef PCP_CBC
  byte *iv = NULL; /*  will be filled during 1st loop */
#endif

  while(!ps_end(in)) {
    cur_bufsize = ps_read(in, &in_buf, PCP_BLOCK_SIZE_IN); /* fread(&in_buf, 1, PCP_BLOCK_SIZE_IN, in); */
    if(cur_bufsize <= PCP_CRYPTO_ADD)
      break; /*  no valid cipher block */

    if(recverify != NULL) {
      if(cur_bufsize < PCP_BLOCK_SIZE_IN || ps_end(in)) {
	/*  pull out signature */
	memcpy(signature_cr, &in_buf[cur_bufsize - siglen_cr], siglen_cr);
	cur_bufsize -= siglen_cr;
      }
    }

#ifdef PCP_CBC
    if(iv == NULL) {
      /*  first block is the IV, don't write it out and skip to the next block */
      iv = ucmalloc(PCP_BLOCK_SIZE);
      memcpy(iv, &in_buf[PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES], PCP_BLOCK_SIZE);
      continue;
    }
#endif

    ciphersize = cur_bufsize - crypto_secretbox_NONCEBYTES;
    memcpy(buf_nonce, in_buf, crypto_secretbox_NONCEBYTES);
    memcpy(buf_cipher, &in_buf[crypto_secretbox_NONCEBYTES], ciphersize);

    es = pcp_sodium_verify_mac(&buf_clear, buf_cipher, ciphersize, buf_nonce, symkey);

#ifdef PCP_CBC
    /*  take last IV and apply it to current clear */
    _xorbuf(iv, buf_clear, cur_bufsize - (PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES));
#endif 

    out_size += ciphersize - PCP_CRYPTO_ADD;

    if(es == 0) {
      ps_write(out, buf_clear, ciphersize - PCP_CRYPTO_ADD);
      /* fwrite(buf_clear, ciphersize - PCP_CRYPTO_ADD, 1, out); */

      if(recverify != NULL)
	crypto_generichash_update(st, buf_clear, ciphersize - PCP_CRYPTO_ADD);

      free(buf_clear);

      if(ps_err(out) != 0) {
	fatal("Failed to write decrypted output!\n");
	out_size = 0;
	break;
      }
    }
    else {
      fatal("Failed to decrypt file content!\n");
      free(buf_clear);
      out_size = 0;
      break;
    }
#ifdef PCP_CBC
    /*  use last cipher as next IV */
    memcpy(iv, &in_buf[PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES], PCP_BLOCK_SIZE);
#endif
  }

  free(buf_nonce);
  free(buf_cipher);

  if(recverify != NULL) {
    /* decrypt the signature */
    memcpy(buf_nonce, signature_cr, crypto_secretbox_NONCEBYTES);

    es = pcp_sodium_verify_mac(&signature, &signature_cr[crypto_secretbox_NONCEBYTES],
			       siglen_cr - crypto_secretbox_NONCEBYTES, buf_nonce, symkey);
    if(es == 0) {
      /* add encrypted recipient list to the hash */
      crypto_generichash_update(st, recverify->cipher, recverify->ciphersize);
      crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

      byte *verifiedhash = NULL;
      verifiedhash = pcp_ed_verify(signature, siglen, recverify->pub);
      if(verifiedhash == NULL)
	out_size = 0;
      else {
	if(memcmp(verifiedhash, hash, crypto_generichash_BYTES_MAX) != 0) {
	  /*  sig verified, but the hash doesn't match */
	  fatal("signed hash doesn't match actual hash of signed decrypted file content\n");
	  out_size = 0;
	}
	free(verifiedhash);
      }
    }
    else {
      fatal("Failed to decrypt signature!\n");
      out_size = 0;
    }
    free(st);
    free(hash);
    free(signature);
    free(signature_cr);
  }

  return out_size;

}

pcp_rec_t *pcp_rec_new(byte *cipher, size_t clen, pcp_key_t *secret, pcp_pubkey_t *pub) {
  pcp_rec_t *r = ucmalloc(sizeof(pcp_rec_t));
  r->cipher = ucmalloc(clen);
  memcpy(r->cipher, cipher, clen);
  r->ciphersize = clen;

  if(secret != NULL) {
    r->secret = ucmalloc(sizeof(pcp_key_t));
    memcpy(r->secret, secret, sizeof(pcp_key_t));
  }
  else
    r->secret = NULL;

  if(pub != NULL) {
    r->pub = ucmalloc(sizeof(pcp_key_t));
    memcpy(r->pub, pub, sizeof(pcp_key_t));
  }
  else
    r->pub = NULL;


  return r;
}

void pcp_rec_free(pcp_rec_t *r) {
  free(r->cipher);

  if(r->secret != NULL) {
    memset(r->secret, 0, sizeof(pcp_key_t));
    free(r->secret);
  }

  if(r->pub != NULL) {
    memset(r->pub, 0, sizeof(pcp_pubkey_t));
    free(r->pub);
  }

  free(r);
}

