from pypcp.dll import *


class Stream(object):
    def __init__(self, backend=None):
        if type(backend) is file:
            fd = open(backend, 'r')
            self._stream = libpcp.ps_new_file(fd)
        elif type(backend) is str:
            buf = libpcp.buffer_new_buf('inbuf', backend, len(backend))
            self._stream = libpcp.ps_new_inbuffer(buf)
        else:
            self._stream = libpcp.ps_new_outbuffer()

    def __del__(self):
        libpcp.ps_close(self._stream)


class Buffer(object):
    def __init__(self, string=None):
        if string:
            self._buffer = libpcp.buffer_new_buf('pybuf', string, len(string))
        else:
            self._buffer = libpcp.buffer_new(32, 'pybuf')

    def __del__(self):
        libpcp.buffer_free(self._buffer)
