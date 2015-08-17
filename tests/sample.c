#include <pcp.h>

int main() {
  Buffer *inbuf;
  pcp_key_t *alice, *bob;
  pcp_pubkey_t *alicepub, *bobpub, *pubhash;
  Pcpstream *clear_in, *crypt_out, *clear_out, *crypt_in;
  PCPCTX *ptx;
  char message[] = "hello world"; 

  /* we always need a context */
  ptx = ptx_new();

  /* generate the keypairs for both */
  alice = pcpkey_new();
  bob = pcpkey_new();

  pcpkey_setowner(alice, "alicia", "alicia@local");

  /* get the public parts of them */
  alicepub = pcpkey_pub_from_secret(alice);
  bobpub = pcpkey_pub_from_secret(bob);

  /* put the clear text message into the stream */
  inbuf = buffer_new(32, "a");
  buffer_add_str(inbuf, message);
  clear_in = ps_new_inbuffer(inbuf);

  /* create the output stream as buffer */
  crypt_out = ps_new_outbuffer();

  /* prepare the pubkey recipient list (only 1 recipient: Bob) */
  pubhash = NULL;
  strncpy(bobpub->id, pcp_getpubkeyid(bobpub), 17);
  HASH_ADD_STR( pubhash, id, bobpub);

  /* actually encrypt the message, don't sign it
     Alice is the sender, Bob is the recipient */
  pcp_encrypt_stream(ptx, clear_in, crypt_out, alice, pubhash, 0, 0);

  /* now, print the encrypted result */
  fprintf(stderr, "Alice encrypted %"FMT_SIZE_T" bytes for Bob:\n", (SIZE_T_CAST)strlen(message));
  buffer_dump(ps_buffer(crypt_out));

  /* ---- encryption done, now decrypt ---- */

  /* prepare the output buffer stream */
  clear_out =  ps_new_outbuffer();

  /* input buffer stream from crypto output */
  crypt_in = ps_new_inbuffer(ps_buffer(crypt_out));
  
  /* in order for the decryptor find the senders public key,
     we need to put it into the context hash. this step can be
     omitted when using a Vault. */
  pcphash_add(ptx, alicepub, alicepub->type);

  buffer_info(crypt_in->b);
  
  /* try to decrypt the message */
  if(pcp_decrypt_stream(ptx, crypt_in, clear_out, bob, NULL, 0, 0) == 0)
    fatals_ifany(ptx);
  else {
    /* and finally print out the decrypted message */
    fprintf(stderr, "Bob decrypted %"FMT_SIZE_T" bytes from Alice:\n", (SIZE_T_CAST)buffer_size(ps_buffer(crypt_out)));
    printf("Decrypted message: %s\n", buffer_get_str(ps_buffer(clear_out)));
  }

  ps_close(clear_in);
  ps_close(crypt_in);
  ps_close(crypt_out);
  ps_close(clear_out);

  ptx_clean(ptx);

  free(alice);
  free(bob);
  free(bobpub);


  
  return 0;
}
