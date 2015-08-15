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




/* asym encr */
byte *pcp_box_encrypt(PCPCTX *ptx, pcp_key_t *secret, pcp_pubkey_t *pub,
			       byte *message, size_t messagesize,
			       size_t *csize) {

  byte *nonce = pcp_gennonce();

  size_t es = messagesize + crypto_box_MACBYTES;
  byte *cipher = ucmalloc(es);

  if(crypto_box_easy(cipher, message, messagesize, nonce, pub->pub, secret->secret) != 0)
    es = 0; /* signal sodium error */

  if(es <= messagesize) {
    fatal(ptx, "failed to encrypt message!\n");
    goto errbec;
  }

  /*  put nonce and cipher together */
  byte *combined = ucmalloc(es + LNONCE);
  memcpy(combined, nonce, LNONCE);
  memcpy(&combined[LNONCE], cipher, es);

  free(cipher);
  free(nonce);

  *csize = es + LNONCE;

  return combined;

 errbec:
  if(cipher != NULL)
    free(cipher);
  free(nonce);

  return NULL;
}


/* asym decr */
byte *pcp_box_decrypt(PCPCTX *ptx, pcp_key_t *secret, pcp_pubkey_t *pub,
			       byte *cipher, size_t ciphersize,
			       size_t *dsize) {

  byte *message = NULL;

  byte *nonce = ucmalloc(LNONCE);
  byte *cipheronly = ucmalloc(ciphersize - LNONCE);

  memcpy(nonce, cipher, LNONCE);
  memcpy(cipheronly, &cipher[LNONCE],
	 ciphersize - LNONCE);

  message = ucmalloc(ciphersize - LNONCE - crypto_box_MACBYTES);
  if(crypto_box_open_easy(message, cipheronly, ciphersize - LNONCE,
			  nonce, pub->pub, secret->secret) != 0) {
    fatal(ptx, "failed to decrypt message!\n");
    goto errbed;
  }

  free(nonce);
  free(cipheronly);

  /*  resulting size: */
  /*  ciphersize - crypto_secretbox_ZEROBYTES */
  *dsize = ciphersize - LNONCE - PCP_CRYPTO_ADD;
  return message;

 errbed:
  free(nonce);
  free(cipheronly);
  if(message != NULL)
    free(message);

  return NULL;
}

/* sym encr */
size_t pcp_sodium_mac(byte **cipher,
		byte *cleartext,
		size_t clearsize,
		byte *nonce,
		byte *key) {

  *cipher = ucmalloc(clearsize + crypto_secretbox_MACBYTES);
  crypto_secretbox_easy(*cipher, cleartext, clearsize, nonce, key);

  return clearsize + crypto_secretbox_MACBYTES;
}

/* sym decr */
int pcp_sodium_verify_mac(byte **cleartext, byte* message,
			  size_t messagesize, byte *nonce,
			  byte *key) {

  *cleartext = ucmalloc(messagesize - crypto_secretbox_MACBYTES);
  return crypto_secretbox_open_easy(*cleartext, message, messagesize, nonce, key);
}


size_t pcp_decrypt_stream(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, pcp_key_t *s, byte *symkey, int verify, int anon) {
  pcp_pubkey_t *cur = NULL;
  byte *reccipher = NULL;
  int recmatch, self;
  uint32_t lenrec;
  byte head[1];
  size_t cur_bufsize, rec_size, nrec;
  byte *rec_buf = NULL;
  pcp_pubkey_t *senderpub = NULL; /* anon only */

  nrec = recmatch = self = 0;

  if(ps_tell(in) > 1) {
    /*  header has already been determined outside the lib */
    if(symkey != NULL)
      self = 1;
  }
  else {
    /*  step 1, check header */
    cur_bufsize = ps_read(in, head, 1); /* fread(head, 1, 1, in); */
    if(cur_bufsize == 1 && !ps_end(in) && !ps_err(in)) {
      if(head[0] == PCP_SYM_CIPHER) {
	if(symkey != NULL)
	  self = 1;
	else {
	  fatal(ptx, "Input is symetrically encrypted but no key have been specified (lib usage failure)\n");
	  goto errdef1;
	}
      }
      else if(head[0] == PCP_ASYM_CIPHER_ANON) {
	self = 0;
	anon = 1;
      }
      else if(head[0] == PCP_ASYM_CIPHER) {
	self = 0;
      }
      else if(head[0] == PCP_ASYM_CIPHER_SIG) {
	self = 0;
	verify = 1;
      }
      else {
	fatal(ptx, "Unknown file header (got: %02x)\n", head[0]);
	goto errdef1;
      }
    }
  }

  if(self) {
    /*  just decrypt symetrically and go outa here */
    return pcp_decrypt_stream_sym(ptx, in, out, symkey, NULL);
  }

  if(anon) {
    /*  step 2, sender's pubkey */
    senderpub = ucmalloc(sizeof(pcp_pubkey_t));
    cur_bufsize = ps_read(in, senderpub->pub, crypto_box_PUBLICKEYBYTES);
    if(cur_bufsize !=  crypto_box_PUBLICKEYBYTES && !ps_end(in) && !ps_err(in)) {
      fatal(ptx, "Error: input file doesn't contain senders public key\n");
      goto errdef1;
    }
  }

  /*  step 3, check len recipients */
  cur_bufsize = ps_read(in, &lenrec, 4); /* fread(&lenrec, 1, 4, in); */
  if(cur_bufsize != 4 && !ps_end(in) && !ps_err(in)) {
    fatal(ptx, "Error: input file doesn't contain recipient count\n");
    goto errdef1;
  }
  lenrec = be32toh(lenrec);
  
  if(verify) {
    reccipher = ucmalloc(lenrec * PCP_ASYM_RECIPIENT_SIZE);
  }



  /*  step 4, fetch recipient list and try to decrypt it for us */
  rec_buf = ucmalloc(PCP_ASYM_RECIPIENT_SIZE);
  for(nrec=0; nrec<lenrec; nrec++) {
    cur_bufsize = ps_read(in, rec_buf, PCP_ASYM_RECIPIENT_SIZE);
    if(cur_bufsize != PCP_ASYM_RECIPIENT_SIZE && !ps_end(in) && !ps_err(in)) {
      fatal(ptx, "Error: input file corrupted, incomplete or no recipients (got %ld, exp %ld)\n",
	    cur_bufsize, PCP_ASYM_RECIPIENT_SIZE );
      ucfree(rec_buf, PCP_ASYM_RECIPIENT_SIZE);
      goto errdef1;
    }
    recmatch = 0;

    if(anon) {
      /* anonymous sender */
      byte *recipient;
      recipient = pcp_box_decrypt(ptx, s, senderpub, rec_buf, PCP_ASYM_RECIPIENT_SIZE, &rec_size);
      if(recipient != NULL && rec_size == crypto_secretbox_KEYBYTES) {
	/*  found a match */
	recmatch = 1;
	symkey = smalloc(crypto_secretbox_KEYBYTES);
	memcpy(symkey, recipient, crypto_secretbox_KEYBYTES);
	free(recipient);
	ucfree(senderpub, sizeof(pcp_pubkey_t));
	break;
      }
      free(recipient);
    }
    else {
      /* dig through our list of known public keys for a match */
      pcphash_iteratepub(ptx, cur) {
	byte *recipient;
	recipient = pcp_box_decrypt(ptx, s, cur, rec_buf, PCP_ASYM_RECIPIENT_SIZE, &rec_size);
	if(recipient != NULL && rec_size == crypto_secretbox_KEYBYTES) {
	  /*  found a match */
	  recmatch = 1;
	  symkey = smalloc(crypto_secretbox_KEYBYTES);
	  memcpy(symkey, recipient, crypto_secretbox_KEYBYTES);
	  free(recipient);
	  break;
	}
	free(recipient);
      }

      /* do the same with our secret keys, just in case the sender used -M */
      if(recmatch == 0) {
	pcp_key_t *k;
	pcphash_iterate(ptx, k) {
	  cur = pcpkey_pub_from_secret(k);
	  byte *recipient;
	  recipient = pcp_box_decrypt(ptx, s, cur, rec_buf, PCP_ASYM_RECIPIENT_SIZE, &rec_size);
	  if(recipient != NULL && rec_size == crypto_secretbox_KEYBYTES) {
	    /*  found a match */
	    recmatch = 1;
	    symkey = smalloc(crypto_secretbox_KEYBYTES);
	    memcpy(symkey, recipient, crypto_secretbox_KEYBYTES);
	    free(recipient);
	    break;
	  }
	}
      }
    }
    if(verify) {
      size_t R = nrec * (PCP_ASYM_RECIPIENT_SIZE);
      memcpy(&reccipher[R], rec_buf, PCP_ASYM_RECIPIENT_SIZE);
    }
  }
  ucfree(rec_buf, PCP_ASYM_RECIPIENT_SIZE);

  if(recmatch == 0) {
    fatal(ptx, "Sorry, there's no matching public key in your vault for decryption\n");
    goto errdef1;
  }

  fatals_reset(ptx);

  /*  step 5, actually decrypt the file, finally */
  if(verify) {
    pcp_rec_t *rec = pcp_rec_new(reccipher, nrec * PCP_ASYM_RECIPIENT_SIZE, NULL, cur);
    size_t s = pcp_decrypt_stream_sym(ptx, in, out, symkey, rec);
    pcp_rec_free(rec);
    ucfree(reccipher, lenrec * PCP_ASYM_RECIPIENT_SIZE);
    sfree(symkey);
    return s;
  }
  else {
    size_t s = pcp_decrypt_stream_sym(ptx, in, out, symkey, NULL);
    sfree(symkey);
    return s;
  }

 errdef1:
  sfree(symkey);
  return 0;
}

size_t pcp_encrypt_stream(PCPCTX *ptx, Pcpstream *in, Pcpstream *out, pcp_key_t *s, pcp_pubkey_t *p, int sign, int anon) {
  byte *symkey;
  int recipient_count;
  byte *recipients_cipher;
  pcp_pubkey_t *cur, *t;
  size_t es;
  int nrec;
  uint32_t lenrec;
  size_t rec_size, out_size;
  byte head[1];

  /*
      6[1]|temp_keypair.pubkey|len(recipients)[4]|(recipients...)|(secretboxes...)
    where recipients is a concatenated list of
      random_nonce|box(temp_keypair.privkey, recipient crypto pk, random_nonce, packet key)
  */

  /*  preparation */
  /*  A, generate sym key */
  symkey = srmalloc(crypto_secretbox_KEYBYTES);

  /*  B, encrypt it asymetrically for each recipient */
  recipient_count = HASH_COUNT(p);
  rec_size = PCP_ASYM_RECIPIENT_SIZE;
  recipients_cipher = ucmalloc(rec_size * recipient_count);
  nrec = 0;

  HASH_ITER(hh, p, cur, t) {
    byte *rec_cipher;
    rec_cipher = pcp_box_encrypt(ptx, s, cur, symkey, crypto_secretbox_KEYBYTES, &es);
    if(es != rec_size) {
      fatal(ptx, "invalid rec_size, expected %dl, got %dl\n", rec_size, es);
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
  if(sign)
    head[0] = PCP_ASYM_CIPHER_SIG;
  else if(anon)
    head[0] = PCP_ASYM_CIPHER_ANON;
  else
    head[0] = PCP_ASYM_CIPHER;
  ps_write(out, head, 1);

  if(ps_err(out) != 0) {
    fatal(ptx, "Failed to write encrypted output!\n");
    goto errec1;
  }

  if(anon) {
    /*  step 2, sender's pubkey */
    ps_write(out, s->pub, crypto_box_PUBLICKEYBYTES);
    /*fwrite(s->pub, crypto_box_PUBLICKEYBYTES, 1, out); */
    /* fprintf(stderr, "D: sender pub - %d\n", crypto_box_PUBLICKEYBYTES); */
    if(ps_err(out) != 0)
      goto errec1;
  }

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
    sym_size = pcp_encrypt_stream_sym(ptx, in, out, symkey, 1, rec);
    pcp_rec_free(rec);
  }
  else
    sym_size = pcp_encrypt_stream_sym(ptx, in, out, symkey, 1, NULL);

  if(sym_size == 0)
    goto errec1;


  sfree(symkey);
  free(recipients_cipher);
  return out_size + sym_size;

 errec1:

  return 0;
}




size_t pcp_encrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream *out, byte *symkey, int havehead, pcp_rec_t *recsign) {
  /*
    havehead = 0: write the whole thing from here
    havehead = 1: no header, being called from asym...
  */

  byte *buf_nonce = NULL;
  byte *buf_cipher = NULL;
  byte *in_buf = NULL;
  size_t cur_bufsize = 0;
  size_t out_size = 0;
  size_t es;
  crypto_generichash_state *st = NULL;
  byte *hash = NULL;
  byte head[1];
  uint64_t ctr = 1;

  if(in->is_buffer) {
    if(buffer_size(in->b) == 0) {
      /* FIXME: add a ps_stream function for this */
      fatal(ptx, "Empty input stream buffer at %p!\n", in->b);
      return 0;
    }
  }
  
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
      fatal(ptx, "Failed to write encrypted output!\n");
      return 0;
    }
  }

  /*  32k-Block-mode. */
  in_buf = ucmalloc(PCP_BLOCK_SIZE);
  while(!ps_end(in)) {
    cur_bufsize = ps_read(in, in_buf, PCP_BLOCK_SIZE);
    if(cur_bufsize <= 0)
      break;

    /* generate nonce and put current buffer counter into it */
    buf_nonce = _gen_ctr_nonce(ctr++);

    es = pcp_sodium_mac(&buf_cipher, in_buf, cur_bufsize, buf_nonce, symkey);
    ps_write(out, buf_nonce, LNONCE);
    ps_write(out, buf_cipher, es);

    out_size += LNONCE + es;

    if(recsign != NULL)
      crypto_generichash_update(st, buf_cipher, es);

    ucfree(buf_nonce, LNONCE);
    free(buf_cipher);
  }

  if(ps_err(out) != 0) {
    free(buf_cipher);
    fatal(ptx, "Failed to write encrypted output!\n");
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

    ps_write(out, buf_nonce, LNONCE);
    ps_write(out, buf_cipher, es);

    free(st);
    free(hash);
    ucfree(buf_nonce, LNONCE);
    free(buf_cipher);
    ucfree(signature, siglen);
  }

  ucfree(in_buf, PCP_BLOCK_SIZE);

  return out_size;

 errsym1:
  if(symkey != NULL) {
    free(st);
    free(hash);
  }
  ucfree(in_buf, PCP_BLOCK_SIZE);
  return 0;
}

size_t pcp_decrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, byte *symkey, pcp_rec_t *recverify) {
  byte *buf_nonce;
  byte *buf_cipher;
  byte *buf_clear;
  size_t out_size, cur_bufsize, es;
  size_t ciphersize = (PCP_BLOCK_SIZE_IN) - LNONCE;
  byte *in_buf = NULL;
  uint64_t ctr, pastctr;
  pastctr = 0;
 
  buf_nonce  = ucmalloc(LNONCE);
  buf_cipher = ucmalloc(ciphersize);
  buf_clear  = ucmalloc(ciphersize);
  out_size = 0;

  byte *signature = NULL;
  byte *signature_cr = NULL;
  size_t siglen = crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  size_t siglen_cr = siglen + PCP_CRYPTO_ADD + LNONCE;
  crypto_generichash_state *st = NULL;
  byte *hash = NULL;

  if(recverify != NULL) {
    st = ucmalloc(sizeof(crypto_generichash_state));
    hash = ucmalloc(crypto_generichash_BYTES_MAX);
    crypto_generichash_init(st, NULL, 0, 0);
    signature_cr = ucmalloc(siglen_cr);
  }


  in_buf = ucmalloc(PCP_BLOCK_SIZE_IN);
  while(!ps_end(in)) {
    cur_bufsize = ps_read(in, in_buf, PCP_BLOCK_SIZE_IN);
    if(cur_bufsize <= PCP_CRYPTO_ADD)
      break; /*  no valid cipher block */

    if(recverify != NULL) {
      if(cur_bufsize < PCP_BLOCK_SIZE_IN || ps_end(in)) {
	/*  pull out signature */
	memcpy(signature_cr, &in_buf[cur_bufsize - siglen_cr], siglen_cr);
	cur_bufsize -= siglen_cr;
      }
    }

    ciphersize = cur_bufsize - LNONCE;
    memcpy(buf_nonce, in_buf, LNONCE);
    memcpy(buf_cipher, &in_buf[LNONCE], ciphersize);

    /* extract counter from nonce and check if it is in line with previous one
       TODO: save unordered buffers to disk and continue writing to out if
       buffers are in order again */
    ctr = _get_nonce_ctr(buf_nonce);
    if(ctr -1 != pastctr) {
      fatal(ptx, "Mangled packet order, bailing out (got: %ld, expected: %ld)!\n",
	    ctr, pastctr+1);
      out_size = 0;
      break;
    }
    pastctr = ctr;
    es = pcp_sodium_verify_mac(&buf_clear, buf_cipher, ciphersize, buf_nonce, symkey);

    out_size += ciphersize - PCP_CRYPTO_ADD;

    if(es == 0) {
      ps_write(out, buf_clear, ciphersize - PCP_CRYPTO_ADD);

      if(recverify != NULL)
	crypto_generichash_update(st, buf_cipher, ciphersize);

      if(ps_err(out) != 0) {
	fatal(ptx, "Failed to write decrypted output!\n");
	out_size = 0;
	break;
      }
    }
    else {
      fatal(ptx, "Failed to decrypt file content!\n");
      out_size = 0;
      break;
    }
  }

  ucfree(in_buf, PCP_BLOCK_SIZE_IN);
  ucfree(buf_cipher, ciphersize);
  ucfree(buf_clear, ciphersize - PCP_CRYPTO_ADD);

  if(recverify != NULL) {
    /* decrypt the signature */
    memcpy(buf_nonce, signature_cr, LNONCE);

    es = pcp_sodium_verify_mac(&signature, &signature_cr[LNONCE],
			       siglen_cr - LNONCE, buf_nonce, symkey);
    if(es == 0) {
      /* add encrypted recipient list to the hash */
      crypto_generichash_update(st, recverify->cipher, recverify->ciphersize);
      crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

      byte *verifiedhash = NULL;
      verifiedhash = pcp_ed_verify(ptx, signature, siglen, recverify->pub);
      if(verifiedhash == NULL)
	out_size = 0;
      else {
	if(memcmp(verifiedhash, hash, crypto_generichash_BYTES_MAX) != 0) {
	  /*  sig verified, but the hash doesn't match */	
	  fatal(ptx, "signed hash doesn't match actual hash of signed decrypted file content\n");
	  out_size = 0;
	}
	free(verifiedhash);
      }
    }
    else {
      fatal(ptx, "Failed to decrypt signature!\n");
      out_size = 0;
    }
    free(st);
    free(hash);
    ucfree(signature, siglen);
    ucfree(signature_cr, siglen_cr);
  }

  free(buf_nonce);

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
    r->pub = ucmalloc(sizeof(pcp_pubkey_t));
    memcpy(r->pub, pub, sizeof(pcp_pubkey_t));
  }
  else
    r->pub = NULL;


  return r;
}

void pcp_rec_free(pcp_rec_t *r) {
  free(r->cipher);

  if(r->secret != NULL) {
    sodium_memzero(r->secret, sizeof(pcp_key_t));
    free(r->secret);
  }

  if(r->pub != NULL) {
    sodium_memzero(r->pub, sizeof(pcp_pubkey_t));
    free(r->pub);
  }

  free(r);
}

/*
  extract buffer counter from given nonce.

  the first byte denotes the size of the
  counter in bytes (1,2,4,...). we extract
  an integer of the given size from the
  bytes afterwards and cast it into an uint64_t,
  convert back to native endianes.
 */
uint64_t _get_nonce_ctr(byte *nonce) {
  uint64_t ctr = 0;
  uint8_t    i = nonce[0];
  uint16_t m16 = 0;
  uint32_t m32 = 0;

  if(i > 16) {
    /* counter bigger than max allowed by protocol, could lead to overflow, therefore die hard here */
    fprintf(stderr, "invalid counter size %d!", i);
    abort();
  }
  
  switch(i) {
  case 1:
    ctr = nonce[1];
    break;
  case 2:
    memcpy(&m16, &nonce[1], 2);
    ctr = be16toh(m16);
    break;
  case 4:
    memcpy(&m32, &nonce[1], 4);
    ctr = be32toh(m32);
    break;
  case 8:
    memcpy(&ctr, &nonce[1], 8);
    ctr = be64toh(ctr);
    break;
  }
  
  return ctr;
}

/*
  generate a new random nonce and put the
  given buffer counter into the front of it.

  the counter has a variable size, starting at
  1 byte. if the counter overflows, we double
  the counter written to the nonce (and modify
  the size indicator accordingly). it will be
  converted to big endian if larger than 1 byte.

  since the nonce has a size of 24 bytes and we use
  the first byte as the size indicator, the maximum
  possible counter size would be a 184 bit integer.
  due to the use of 32kb input buffers, encryption
  is limited to files with a maximum size of
  784.637.716.923.335.095.479.473.677.900.958.302.012.794.430.558.004.314.112.000 bytes.

  sapperlot, did I really put this number in here?

  back to reality: while this protocol allows
  184 bit counters, my current implementation
  is limited to 64 bit counters, which results
  in a maximum file size of around 590 zetta bytes
  or 590 sextillion bytes. 'nough time to learn
  big integer crunching...

  why?

  we use a varable size counter, because in this
  way we avoid nonces with an insufficient amount
  of randomness. compare these two examples:

  0101da63b0a8b1d4e7c32b367b7deedb8032604ed45bdf34

  vs:

  01000000000000000183475b2969bbb20a03ff41e8002659

  the first nonce uses a variable sized counter
  (1 byte) with the value 1 and the latter a fixed
  size 64bit counter also with the value 1. as you
  can see, it only contains 15 random bytes, 7 bytes
  are just zeros.

  also, I assume that such large inputs will
  be very rare, so in almost all cases we would end
  up with just 15 or 14 random bytes. that's beyond
  the idea of nacl's crypto_box, unacceptable and
  doesn't look the way I'm accustomed. hence variable
  size counters.

  returns the counter nonce.
 */
byte *_gen_ctr_nonce(uint64_t ctr) {
  uint8_t  m8  = -1;
  uint16_t m16 = -1;
  uint32_t m32 = -1;
  uint64_t m64 = -1;
  uint8_t    i = 1;
  
  byte *nonce = pcp_gennonce();

  if(ctr > m32) {
    i = 8;
    m64 = htobe64(ctr);
    memcpy(&nonce[1], &m64, 8);
  }
  else if(ctr < m32 && ctr > m16) {
    i = 4;
    m32 = htobe32(ctr);
    memcpy(&nonce[1], &m32, 4);
  }
  else if(ctr < m16 && ctr > m8) {
    i = 2;
    m16 = htobe16(ctr);
    memcpy(&nonce[1], &m16, 2);
  }
  else {
    i = 1;
    nonce[1] = ctr;
  }
  nonce[0] = i;

  return nonce;
}

/*
TODO: how to go past 64 bits:
http://mrob.com/pub/math/int128.c.txt
http://locklessinc.com/articles/256bit_arithmetic/
*/

int pcp_checksum(PCPCTX *ptx, Pcpstream *in, byte *checksum, byte *key, size_t keylen) {
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  byte *buf = ucmalloc(PCP_BLOCK_SIZE);
  size_t bufsize = 0;
  int ret = 1;

  
  if(key != NULL && keylen <= crypto_generichash_KEYBYTES_MAX) {
    crypto_generichash_init(st, key, keylen, crypto_generichash_KEYBYTES_MAX);
  }
  else
    crypto_generichash_init(st, NULL, 0, 0);
  
  while(!ps_end(in)) {
    bufsize = ps_read(in, buf, PCP_BLOCK_SIZE);
    crypto_generichash_update(st, buf, bufsize);
  }
  
  crypto_generichash_final(st, checksum, crypto_generichash_BYTES_MAX);

  if(ps_err(in)) {
    ret = 0;
    fatal(ptx, "Error while reading file!\n");
  }
  
  free(st);
  free(buf);

  return ret;
}
