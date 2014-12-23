from pypcp.dll import *
from pypcp.stream import *

class Context(object):
    def __init__(self):
        self._ctx = libpcp.ptx_new()
        self._sk = None

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

    def addkey(self, Key):
        self._sk = Key._sk

    def pubkeycount(self):
        return libpcp.pcphash_countpub(self._ctx)

    def recipients(self, *recipients):
        for key in recipients:
            libpcp.pcphash_add(self._ctx, key._pk, key._pk.type)

    def encrypt(self, source=None, sign=False, passphrase=None, armor=False):
        anon = 0
        dosign = 0
        instream = None
        outstream = None
        
        if source:
            instream = Stream(source)
        else:
            self.throw(RuntimeError, "source argument required")

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
                
            if sign:
                dosign = 1

            size = libpcp.pcp_encrypt_stream(self._ctx, instream._stream, outstream._stream,
                                             self._sk, self._ctx.pcppubkey_hash, dosign, anon)
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
                self.throw(RuntimeError, "no secret key associated with current context")

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
