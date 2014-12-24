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

class PublicKey(object):
    """
    A libpcp public key object.
    """
    def __init__(self, pk=None, encoded=None):
        """
        Import a public key.

        'encoded' can be a file handle (returned by open()) or a python string
        containing the public key.
        """
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
        """
        Internal method to import a key from the outside.
        """
        ks = libpcp.pcp_import_pub(context._ctx, encoded, len(encoded))
        if not ks:
            context.throw(IOError, "failed to import key")
        self._pk = ks.p

    def dump(self):
        """
        Dump the contents of the key to STDERR.
        """
        if self._pk:
            libpcp.pcp_dumppubkey(self._pk)

    def __dict__(self):
        return convert_to_python(self._pk)
