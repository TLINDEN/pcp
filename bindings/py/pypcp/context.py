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
from pypcp.stream import *

class Context(object):
    """
    A libpcp context object, required for all operations.
    """
    def __init__(self):
        """
        Create a new instance:
        
        >>> ctx = Context()
        """
        self._ctx = libpcp.ptx_new()
        self._sk = None

    def __del__(self):
        """
        Destructor, automatically called
        """
        libpcp.ptx_clean(self._ctx)

    def throw(self, E=None, msg=None):
        """
        Used internally to propagate libpcp errors.

        Throw libpcp error:
        >>> ctx.throw(IOError, "additional message")

        Throw pure python exception:
        >>> ctx.throw(None, "pypcp error")
        """
        # forward libpcp generated exceptions
        pcpmsg = ''

        if self._ctx.pcp_errset == 1:
            pcpmsg = ffi.string(self._ctx.pcp_err)

        if E:
            if msg:
                pcpmsg = "%s: %s" % (msg, pcpmsg)
            raise E(pcpmsg)
        else:
            raise RuntimeError(msg)

    def addkey(self, Key):
        """
        Add a secret key to the contect. Required for encryption
        and signing operations. If you don't add a secret key to
        the context, anonymous encryption will be done.

        >>> key = Key(owner="alicia")
        >>> ctx.addkey(key)
        """
        self._sk = Key._sk

    def pubkeycount(self):
        """
        Return the number of public keys known.
        """
        return libpcp.pcphash_countpub(self._ctx)

    def recipients(self, *recipients):
        """
        Add one or more public keys. Required for encryption
        and signing operations.

        >>> keyfile = open("bobby.pub", "r")
        >>> bobby = PublicKey(encoded=keyfile).read()
        >>> ctx.recipients(bobby)
        """
        for key in recipients:
            libpcp.pcphash_add(self._ctx, key._pk, key._pk.type)

    def encrypt(self, source=None, sign=False, passphrase=None, armor=False):
        """
        Encrypt a file or a string.

        Args:
        - 'source' can be a file handle (returned by open())
          or a python string containing the data to be encrypted
        - 'sign': if set to True, append a signature to encrypted output
        - 'passphrase': If set, do symmetric encryption (self mode)
        - 'armor': if set to True, encode the output using Z85

        Returns:
        returns the encrypted result.

        Encrypt asymmetrically:
        >>> seca = Key(encoded=alicesec, 'a')                # import keys
        >>> secb = Key(encoded=bobsec, 'b')
        >>> puba = PublicKey(encoded=alicepub)
        >>> pubb = PublicKey(encoded=bobpub)
        >>>
        >>> ctxA = Context()                                 # 2 contexts, one for sender, one for recipient
        >>> ctxA.addkey(seca)
        >>> ctxA.recipients(pubb)
        >>> ctxB = Context()
        >>> ctxB.addkey(secb)
        >>> ctxB.recipients(puba)
        >>>
        >>> encrypted = ctxA.encrypt(source='hello world')   # encrypt alice => bob
        >>> decrypted = ctxB.decrypt(source=encrypted)       # decrypt bob <= alice

        Encrypt symmetrically:
        >>> ctx = Context()
        >>> encrypted = ctx.encrypt(source='hello world', passphrase='x')
        >>> decrypted = ctx.decrypt(source=encrypted, passphrase='x')

        """
        anon = 0
        dosign = 0
        instream = None
        outstream = None
        sk = self._sk
        
        if source:
            instream = Stream(source)
        else:
            self.throw(None, "source argument required")

        outstream = Stream()
        
        if armor:
            # enable z85 encoding
            libpcp.ps_armor(outstream._stream, PCP_BLOCK_SIZE/2)
            libpcp.ps_print(outstream._stream, PCP_ENFILE_HEADER)

        if self.pubkeycount() > 0:
            # asymmetric

            if not self._sk:
                # no secret key known, anonymous mode
                anon = 1
                sk = libpcp.pcpkey_new()
                
            if sign:
                dosign = 1

            size = libpcp.pcp_encrypt_stream(self._ctx, instream._stream, outstream._stream,
                                             sk, self._ctx.pcppubkey_hash, dosign, anon)
            if size <= 0:
                self.throw(IOError, "failed to encrypt")

        else:
            # symmetric
            salt = ffi.new("byte[]", PBP_COMPAT_SALT)
            symkey = libpcp.pcp_scrypt(self._ctx, passphrase, len(passphrase), salt, 90)
            size =  libpcp.pcp_encrypt_stream_sym(self._ctx, instream._stream,
                                                  outstream._stream, symkey, 0, ffi.NULL)
            if size <= 0:
                self.throw(IOError, "failed to encrypt")


        if armor:
            # finish z85 encoding
            libpcp.ps_finish(outstream._stream);
            libpcp.ps_unarmor(outstream._stream);
            libpcp.ps_print(outstream._stream, PCP_ENFILE_FOOTER)

        # return the raw buffer contents, wether encoded or not
        return ffi.buffer(libpcp.buffer_get_remainder(outstream._stream.b),
                          libpcp.buffer_size(outstream._stream.b))[:]



    def decrypt(self, source=None, verify=False, passphrase=None):
        """
        Decrypt a file or string

        Args:
        - 'source' can be a file handle (returned by open())
          or a python string containing the data to be encrypted
        - 'verify': if set to True, verify a signature, if present
        - 'passphrase': If set, do symmetric encryption (self mode)

        Returns:
        returns the decrypted result.

        For usage example see encrypt().
        """
        doverify = 0
        doanon = 0
        instream = None
        outstream = None

        if verify:
            doverify = 1

        if source:
            instream = Stream(source)
        else:
            self.throw(RuntimeError, "source argument required")

        libpcp.ps_setdetermine(instream._stream, PCP_BLOCK_SIZE/2)
        outstream = Stream()

        # determine input type
        head = ffi.new("byte *")
        got = libpcp.ps_read(instream._stream, head, 1)

        if got <= 0:
            self.throw(IOError, "failed to read from input stream")

        if head[0] == PCP_SYM_CIPHER:
            # symmetric
            salt = ffi.new("byte[]", PBP_COMPAT_SALT)
            symkey = libpcp.pcp_scrypt(self._ctx, passphrase, len(passphrase), salt, 90)
            size = libpcp.pcp_decrypt_stream(self._ctx, instream._stream,
                                             outstream._stream, ffi.NULL,
                                             symkey, doverify, 0)
            if size <= 0:
                self.throw(IOError, "failed to decrypt")
        else:
            # asymmetric
            if not self._sk:
                self.throw(None, "no secret key associated with current context")

            if head[0] == PCP_ASYM_CIPHER_ANON:
                doanon = 1
            if head[0] == PCP_ASYM_CIPHER_SIG:
                doverify

            size = libpcp.pcp_decrypt_stream(self._ctx, instream._stream,
                                             outstream._stream, self._sk,
                                             ffi.NULL, doverify, doanon)
            if size <= 0:
                self.throw(IOError, "failed to decrypt")

        # return the raw buffer contents
        return ffi.buffer(libpcp.buffer_get_remainder(outstream._stream.b),
                          libpcp.buffer_size(outstream._stream.b))[:]
