from cffi import FFI
from pypcp.dll import *
from pprint import pprint

__all__ = ('raw Key PublicKey'.split() )

# https://gist.github.com/inactivist/4ef7058c2132fa16759d

class Context(object):
    def __init__(self):
        self._ctx = libpcp.ptx_new()

    def __del__(self):
        libpcp.ptx_clean(self._ctx)

    def throw(self, E=None, msg=None):
        # forward libpcp generated exceptions
        pcpmsg = ffi.string(self._ctx.pcp_err)
        if msg:
            pcpmsg = "%s: %s" % (msg, pcpmsg)
        if E:
            raise E(pcpmsg)
        else:
            raise RuntimeError(pcpmsg)

class PublicKey(object):
    def __init__(self, pk=None, encoded=None):
        self._pk = None

        if pk:
            self._pk = pk
        elif encoded:
            self.importkey(Context(), encoded)
        else:
            self._pk = ffi.new("struct _pcp_pubkey_t*")

        for key, value in convert_to_python(self._pk).iteritems():
            self.__setattr__(key, value)

    def importkey(self, context, encoded=None):
        ks = libpcp.pcp_import_pub(context._ctx, encoded, len(encoded))
        if not ks:
            context.throw(IOError, "failed to import key")
        self._pk = ks.p

    def dump(self):
        if self._pk:
            libpcp.pcp_dumppubkey(self._pk)

    def __dict__(self):
        return convert_to_python(self._pk)

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
            self._sk = ffi.new("struct pcp_key_t*")

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
            
