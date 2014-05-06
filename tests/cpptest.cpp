#include <pcp++.h>
#include <string>
#include <iomanip>
#include <fstream>

using namespace pcp;
using namespace std;

void pr(string name, unsigned char *data, size_t len) {
  size_t i;
  cout << name << ": ";
  for ( i = 0;i < len;++i)
    printf("%02x", (unsigned int) data[i]);
  cout << endl;
}

FILE *_openwr(string file, PcpContext &ptx) {
  FILE *fd;
  if((fd = fopen(file.c_str(), "wb+")) == NULL) {
    throw pcp::exception(ptx, "Could not open output file " + file + "\n");
  }
  return fd;
}

FILE *_openrd(string file, PcpContext &ptx) {
  FILE *fd;
  if((fd = fopen(file.c_str(), "rb")) == NULL) {
    throw pcp::exception(ptx, "Could not open input file " + file + "\n");
  }
  return fd;
}

void test0() {
  // test keygen and crypto
  PcpContext CA; // we need different contexts for sender and recipient!
  PcpContext CB;

  FILE *CLEAR, *CIPHER, *DECRYPTED;
  Key A = Key(CA, "a", "alicia", "alicia@local");
  Key B = Key(CA, "b", "bobby",  "bobby@local");
  PubKey PA = A.get_public();
  PubKey PB = B.get_public();

  A.decrypt("a");
  B.decrypt("b");
  
  Crypto A2B(CA, A, PB);
  Crypto B2A(CB, B, PA);

  CLEAR = _openwr("testcppclear", CA);
  fprintf(CLEAR, "HALLO\n");
  fclose(CLEAR);
  
  CIPHER = _openwr("testcpcipher", CA);
  CLEAR = _openrd("testcppclear", CA);

  if(A2B.encrypt(CLEAR, CIPHER, false)) {

    CIPHER = _openrd("testcpcipher", CA);
    DECRYPTED = _openwr("testcppdecrypted", CA);

    if(B2A.decrypt(CIPHER, DECRYPTED, false)) {

      DECRYPTED = _openrd("testcppdecrypted", CA);
      char *got = (char *)ucmalloc(10);
      if(fread(got, 1, 6, DECRYPTED) < 6) {
	throw pcp::exception(CA, "read error, could not read decrypted content");
      }
      if(strncmp(got, "HALLO", 5) != 0) {
	throw pcp::exception(CA);
      }
    }
    else
      throw pcp::exception(CA, "failed to decrypt");
  }
  else
    throw pcp::exception(CA, "failed to encrypt");

  cout << "0 ok" << endl;

  CA.done();
  CB.done();
}

void test1(PcpContext &ptx) {
  // test the vault
  Key A = Key(ptx, "a", "alicia", "alicia@local");
  Key B = Key(ptx, "b", "bobby",  "bobby@local");
  PubKey PA = A.get_public();
  PubKey PB = B.get_public();

  Vault vault = Vault(ptx, "vcpp1");
  vault.key_add(A);
  vault.pubkey_add(PB);

  KeyMap m = vault.keys();
  bool gotp, gots;
  gotp = gots = false;
  for(KeyIterator it=m.begin(); it != m.end(); ++it) {
    if(it->first == A.get_id())
      gots = true;
  }

  PubKeyMap p = vault.pubkeys();
  for(PubKeyIterator it=p.begin(); it != p.end(); ++it) {
    if(it->first == PB.get_id())
      gotp = true;
  }

  if(gotp == false || gots == false)
    throw pcp::exception(ptx, "wtf - didnt find installed keys");
  else
    cout << "1 ok" << endl;
}

void test2(PcpContext &ptx) {
  // try importing a key from disk
  ifstream pf("key-bobby-pub");
  string z;
  int max = 1024;
  char buf[max];
  while(pf) {
    pf.getline(buf, max);
    if(strlen(buf) > 0)
      z += buf + string("\n");
  }
  PubKey B(ptx, z);
  //cout << B.to_text();
  cout << "2 ok" << endl;
}


void test3(PcpContext &ptx) {
  // signature test
  Key A = Key(ptx, "a", "alicia", "alicia@local");
  A.decrypt("a");
  PubKey PA = A.get_public();

  string message = "hallo baby";

  Signature SigA(ptx, A);
  Signature SigB(ptx, PA);

  if(SigA.sign((unsigned char*)message.c_str(), message.length()))
    if(SigB.verify(SigA.sig) )
      cout << "3 ok" << endl;
}

void test4() {
  unsigned char *r = (unsigned char*)ucmalloc(32);
  int i;
  Buf b;

  for(i=0; i<10; i++) {
    arc4random_buf(r, 32);
    b.add(r, 32);
  }

  if(b.size() == 32 * 10)
    cout << "4 ok" << endl;
  else
    cout << "4 failed" << endl;
}

int main(int argc, char **argv) {
  sodium_init();
  PcpContext ptx;

  try {
    if(argc < 2)
      throw pcp::exception(ptx, "usage: cpptest N");
    switch(argv[1][0]) {
    case '0':
      test0();
      break;

    case '1':
      test1(ptx);
      break;

    case '2':
      test2(ptx);
      break;

    case '3':
      test3(ptx);
      break;

    case '4':
      test4();
      break;

    default:
      cerr << "usage: cpptest N" << endl;
      break;
    };
  }
  catch (pcp::exception &E) {
    cerr << "Catched exception: " << E.what() << endl;
  }

  ptx.done();

  return 0;
}
