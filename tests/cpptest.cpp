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

void test0() {
  // test keygen and crypto
  Key A = Key("a", "alicia", "alicia@local");
  Key B = Key("b", "bobby",  "bobby@local");
  PubKey PA = A.get_public();
  PubKey PB = B.get_public();

  A.decrypt("a");
  B.decrypt("b");
  
  Crypto A2B(A, PB);
  Crypto B2A(B, PA);
  
  string cipher = A2B.encrypt("Hallo");
  ResultSet res = B2A.decrypt(cipher);

  if(res.String == "Hallo")
    cout << "0 ok" << endl;
  else
    throw pcp::exception("wtf - decryption failed (uncatched as well)");
}

void test1() {
  // test the vault
  Key A = Key("a", "alicia", "alicia@local");
  Key B = Key("b", "bobby",  "bobby@local");
  PubKey PA = A.get_public();
  PubKey PB = B.get_public();

  Vault vault = Vault("vcpp1");
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
    throw pcp::exception("wtf - didnt find installed keys");
  else
    cout << "1 ok" << endl;
}

void test2() {
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
  PubKey B(z);
  //cout << B.to_text();
  cout << "2 ok" << endl;
}


void test3() {
  // signature test
  Key A = Key("a", "alicia", "alicia@local");
  A.decrypt("a");
  PubKey PA = A.get_public();

  string message = "hallo baby";

  Signature SigA(A);
  Signature SigB(PA);

  unsigned char *sig = SigA.sign((unsigned char*)message.c_str(), message.length());

  // FIXME: bad api here
  if(SigB.verify(sig, message.length() + crypto_sign_BYTES) )
    cout << "3 ok" << endl;
}

int main(int argc, char **argv) {
  sodium_init();

  try {
    if(argc < 2)
      throw pcp::exception("usage: cpptest N");
    switch(argv[1][0]) {
    case '0':
      test0();
      break;

    case '1':
      test1();
      break;

    case '2':
      test2();
      break;

    case '3':
      test3();
      break;

    default:
      cerr << "usage: cpptest N" << endl;
      break;
    };
  }
  catch (pcp::exception &E) {
    cerr << "Catched exception: " << E.what() << endl;
  }
  return 0;
}
