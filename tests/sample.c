#include <pcp.h>

int main() {
  Buffer *inbuf;
  pcp_key_t *alice, *bob;
  pcp_pubkey_t *alicepub, *bobpub, *pubhash;
  Pcpstream *clear_in, *crypt_out, *clear_out;
  char message[] = "hello world"; 

  /* generate the keypairs for both */
  alice = pcpkey_new();
  bob = pcpkey_new();

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
  pcp_encrypt_stream(clear_in, crypt_out, alice, pubhash, 0);

  /* now, print the encrypted result */
  fprintf(stderr, "Alice encrypted %ld bytes for Bob:\n", strlen(message));
  buffer_dump(ps_buffer(crypt_out));

  /* ---- encryption don, now decrypt ---- */

  /* prepare the output buffer stream */
  clear_out =  ps_new_outbuffer();

  /* in order for the decryptor find the senders public key,
     we need to put it into the global hash. this step can be
  omitted when using a Vault. */
  pcppubkey_hash = NULL;
  HASH_ADD_STR( pcppubkey_hash , id, alicepub);

  /* try to decrypt the message */
  if(pcp_decrypt_stream(crypt_out, clear_out, bob, NULL, 0) == 0)
    fatals_ifany();
  else {
    /* and finally print out the decrypted message */
    fprintf(stderr, "Bob decrypted %ld bytes from Alice:\n", buffer_size(ps_buffer(crypt_out)));
    printf("Decrypted message: %s\n", buffer_get_str(ps_buffer(clear_out)));
  }

  ps_close(clear_in);
  ps_close(crypt_out);
  ps_close(clear_out);

  free(alice);
  free(alicepub);
  free(bob);
  free(bobpub);

  return 0;
}
