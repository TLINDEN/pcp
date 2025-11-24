# -*-python-*-


libincludes = include_directories('include', 'include/pcp')

# check for libraries with CMAKE or pkg-config
sodium = dependency('libsodium')

# manually check for libraries
jansson = c.find_library('jansson', required: true,
               dirs : ['/usr', '/usr/local'])

conf.set('HAVE_SODIUM', sodium.found())
conf.set('HAVE_JSON', jansson.found())

math = c.find_library('m')

# add dependencies, manual libs are added directly below
pcp_deps = [
    sodium, jansson, math
]


libpcp = shared_library(
    'pcp',
    'buffer.c',
    'context.c',
    'crypto.c',
    'ed.c',
    'getpass.c',
    'jenhash.c',
    'key.c',
    'keyhash.c',
    'keysig.c',
    'mem.c',
    'mgmt.c',
    'pcpstream.c',
    'platform.c',
    'randomart.c',
    'readpass.c',
    'scrypt.c',
    'util.c',
    'vault.c',
    'version.c',
    'z85.c',
    'zmq_z85.c',
    include_directories: libincludes,
    install: true,
    dependencies: pcp_deps
)

libpcp_dep = declare_dependency(
    include_directories: libincludes,
    link_with: libpcp,
)



# write out the config header
m = configure_file(
  input : 'config.h.in',
  output : 'config.h',
  configuration : conf,
)
