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

    def encrypt(self, string=None, file=None, sign=False, passphrase=None):
        anon = 0
        instream = None
        outstream = None
        
        if string:
            instream = Stream(string=string)
        else:
            instream = Stream(file)

        outstream = Stream()
            
        if self.pubkeycount() > 0:
            if not self._sk:
                anon = 1
                
            dosign = 0
            if sign:
                dosign = 1

            size = libpcp.pcp_encrypt_stream(self._ctx, instream._stream, outstream._stream,
                                             self._sk, self._ctx.pcppubkey_hash, dosign, anon)

            if size <= 0:
                self.throw(IOError, "failed to encrypt")

            return ffi.buffer(libpcp.buffer_get_remainder(outstream._stream.b), libpcp.buffer_size(outstream._stream.b))[:]
            
        else:
            # symmetric
            salt = ffi.new("byte[]", PBP_COMPAT_SALT)
            symkey = libpcp.pcp_scrypt(self._ctx, passphrase, len(passphrase), salt, 90);
            size =  libpcp.pcp_encrypt_stream_sym(self._ctx, instream._stream, outstream._stream, symkey, 0, ffi.NULL)

            if size <= 0:
                self.throw(IOError, "failed to encrypt")

            return ffi.buffer(libpcp.buffer_get_remainder(outstream._stream.b), libpcp.buffer_size(outstream._stream.b))[:]
