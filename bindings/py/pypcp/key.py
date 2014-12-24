#
#    This file is part of Pretty Curved Privacy (pcp1).
#
#    Copyright (C) 2013-2015 T. von Dein.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    You can contact me by mail: <tlinden AT cpan DOT org>.
#
from pypcp.dll import *
from pypcp.context import *

class Key(object):
    """
    A libpcp secret key object.
    """
    def __init__(self, owner=None, mail=None, sk=None, encoded=None, passphrase=None):
        """
        Create a new secret key or import one.

        If 'owner' or 'mail' are set, a new secret key will be generated.

        If 'encoded' is provided, a key will be imported, 'encoded' can be a file
        handle (returned by open()) or a python string. If the key is encrypted,
        you need to supply 'passphrase' as well.

        Without arguments an empty key object will be used. Don't do that.
        """
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
        """
        Internal method to import a key from the outside.
        """
        sk = libpcp.pcp_import_secret(context._ctx, encoded, len(encoded), passphrase)
        if not sk:
            context.throw(IOError, "failed to import key")
        self._sk = sk

    def generate(self, owner=None, mail=None):
        """
        Internal method to generate a new secret key.
        """
        self._sk = libpcp.pcpkey_new()
        if owner:
            libpcp.pcpkey_setowner(self._sk, owner, mail)

    def dump(self):
        """
        Dump the contents of the key to STDERR.
        """
        if self._sk:
            libpcp.pcp_dumpkey(self._sk)
