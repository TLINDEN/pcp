from pypcp.dll import *
from pypcp.context import *

class Key(object):
    def __init__(self, owner=None, mail=None, sk=None, encoded=None, passphrase=None):
        self._sk = None

        if owner or mail:
            # generate new one
            if not owner:
                owner=''
            if not mail:
                mail=''
            self.generate(owner, mail)
        elif sk:
            # use the raw sk
            self._sk = sk
        elif encoded:
            # import an encoded key
            self.importkey(Context(), encoded, passphrase)
        else:
            self._sk = ffi.new("struct _pcp_key_t*")

        # just for convenience
        for key, value in convert_to_python(self._sk).iteritems():
            self.__setattr__(key, value)

    def importkey(self, context, encoded=None, passphrase=None):
        sk = libpcp.pcp_import_secret(context._ctx, encoded, len(encoded), passphrase)
        if not sk:
            context.throw(IOError, "failed to import key")
        self._sk = sk

    def generate(self, owner=None, mail=None):
        self._sk = libpcp.pcpkey_new()
        if owner:
            libpcp.pcpkey_setowner(self._sk, owner, mail)

    def dump(self):
        if self._sk:
            libpcp.pcp_dumpkey(self._sk)
