from raw import *
from static import *

from cffi import FFI

ffi = FFI()

libpcp = ffi.dlopen('libpcp1.so.0')

ffi.cdef("%s\n%s\n" % (STATIC, PCP_RAW_CODE))
