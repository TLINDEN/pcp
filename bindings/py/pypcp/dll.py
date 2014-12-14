from raw import *
from static import *

from cffi import FFI

# from:
# https://gist.github.com/inactivist/4ef7058c2132fa16759d
# with fixes

def __convert_struct_field( s, fields ):
    for field,fieldtype in fields:
        if fieldtype.type.kind == 'primitive':
            yield (field,getattr( s, field ))
        else:
            yield (field, convert_to_python( getattr( s, field ) ))

def convert_to_python(s):
    type=ffi.typeof(s)
    if type.item.kind == 'struct':
        return dict(__convert_struct_field( s, type.item.fields ) )
    elif type.kind == 'array':
        if type.item.kind == 'primitive':
            if type.item.cname == 'char':
                return ffi.string(s)
            else:
                return [ s[i] for i in range(type.length) ]
        else:
            return [ convert_to_python(s[i]) for i in range(type.length) ]
    elif type.kind == 'primitive':
        return int(s)

ffi = FFI()

libpcp = ffi.dlopen('libpcp1.so.0')

ffi.cdef("%s\n%s\n" % (STATIC, PCP_RAW_CODE))
