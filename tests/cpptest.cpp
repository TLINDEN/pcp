#include <pcp++.h>
#include <string>

using namespace pcp;
using namespace std;

void pr(string name, unsigned char *data, size_t len) {
  int i;
  cout << name << ": ";
  for ( i = 0;i < len;++i)
    printf("%02x", (unsigned int) data[i]);
  cout << endl;
}


int main() {
  try {
    Key A = Key("a", "alicia", "alicia@local");
    Key B = Key("b", "bobby",  "bobby@local");
    PubKey PA = A.get_public();
    PubKey PB = B.get_public();

    A.decrypt("a");
    B.decrypt("b");

    pr("A secret", A.K->secret, 32);
    pr("A public", A.K->pub, 32);
    pr("B secret", B.K->secret, 32);
    pr("B public", B.K->pub, 32);


    string cipher = A.encrypt(PB, "Hallo");
    ResultSet res = B.decrypt(PA, cipher);

    cout << " Input: Hallo" << endl;
    cout << "Cipher: " << cipher << endl;
    cout << " Clear: " << res.String << endl;

    Vault vault = Vault("vcpp");
    vault.key_add(A);
    vault.pubkey_add(PB);

    KeyMap m = vault.keys();
    for(KeyIterator it=m.begin(); it != m.end(); ++it) {
      cout << "id: " << it->first << endl;
    }

    PubKeyMap p = vault.pubkeys();
    for(PubKeyIterator it=p.begin(); it != p.end(); ++it) {
      cout << "id: " << it->first << endl;
    }
  }
  catch (pcp::exception &E) {
    cerr << "Catched exception: " << E.what() << endl;
  }
  return 0;
}
