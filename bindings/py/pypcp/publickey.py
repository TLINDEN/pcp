from pypcp.dll import *
from pypcp.context import *

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
