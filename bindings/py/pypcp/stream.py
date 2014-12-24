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


class Stream(object):
    """
    libpcp Stream object, used by pypcp to interact with libpcp.
    """
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
    """
    libpcp Buffer object, used by pypcp to interact with libpcp.
    """
    def __init__(self, string=None):
        if string:
            self._buffer = libpcp.buffer_new_buf('pybuf', string, len(string))
        else:
            self._buffer = libpcp.buffer_new(32, 'pybuf')

    def __del__(self):
        libpcp.buffer_free(self._buffer)
