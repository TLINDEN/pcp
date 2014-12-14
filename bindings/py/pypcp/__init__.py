from cffi import FFI
from pypcp.dll import *

__all__ = ('raw Key'.split() )


class Key(object):
    def __init__(self, owner=None, mail=None, sk=None):
        self._sk = None
        if owner or mail:
            if not owner:
                owner=''
            if not mail:
                mail=''
            self.generate(owner, mail)

    def generate(self, owner=None, mail=None):
        self._sk = libpcp.pcpkey_new()
        if owner:
            libpcp.pcpkey_setowner(self._sk, owner, mail)

    def dump(self):
        if self._sk:
            libpcp.pcp_dumpkey(self._sk)
            
