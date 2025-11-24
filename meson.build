# -*-python-*-

project(
        'pcp',
        'c',
        license: 'GPL',
        version: '0.4.1',
        meson_version: '>=1.3',
        default_options: [
                'warning_level=2',
                'werror=true',
        ],
)

add_project_arguments(
        [
                '-Wno-unused-parameter',
                '-Wno-unused-result',
                '-Wno-missing-braces',
                '-Wno-format-zero-length',
                '-Wno-implicit-fallthrough',
                #'-Wvla',
                '-Wno-sign-compare',
                '-Wno-narrowing'
        ],
        language: 'c',
)


c = meson.get_compiler('c')
conf = configuration_data()
pcp_inc = include_directories('src', 'libpcp')


if host_machine.system().startswith('freebsd')
  pcp_inc = include_directories('.', '/usr/local/include')
  add_project_link_arguments('LDFLAGS=/usr/local/lib')
endif



# check for funcs.
foreach func : ['getopt', 'fdopen', 'fgetc', 'getenv', 'getpass', 'arc4random', 'fopen', 'fread', 'fwrite', 'ftruncate', 'fprintf', 'isatty', 'malloc', 'memset', 'memcpy', 'perror', 'posix_memalign', 'setrlimit', 'strnlen', 'strlen', 'strtol', 'tcgetattr', 'umask', 'towlower', 'getopt', 'getopt_long', 'vasprintf',]
    conf.set('HAVE_'+func.to_upper(),
             c.has_function(
                 func,
                 prefix : '#include <unistd.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <sys/resource.h>\n#include <string.h>\n#include <sys/stat.h>\n#include <termios.h>\n#include <wctype.h>\n#include <getopt.h>',
             )
    )
endforeach

if host_machine.system().startswith('freebsd')
   conf.set('HAVE_STRNSTR',
            c.has_function(
                'strnstr',
                prefix: '#include <string.h>'
            ))
else
   bsd = c.find_library('bsd')
   conf.set('HAVE_STRNSTR',
            c.has_function(
                'strnstr',
                prefix: '#include <bsd/string.h>',
                dependencies: bsd,
            ))
   add_project_dependencies(bsd, language: 'c')
endif


# check commandline options
prefix = get_option('prefix')

if get_option('buildtype') == 'debug'
    conf.set('DEBUG', '1')
endif



# setup conf map
version = '@0@'.format(meson.project_version())

conf.set('prefix', prefix)
conf.set('VERSION', version)

subdir('libpcp')




# code
pcp_sources = files(
    'src/compat_getopt.c',
    'src/encryption.c',
    'src/keymgmt.c',
    'src/keyprint.c',
    'src/pcp.c',
    'src/signature.c',
    'src/z85util.c'
)


executable(
        'pcp',
        [pcp_sources],
        include_directories: [pcp_inc],
        dependencies: [libpcp_dep, jansson],
        install: true
)

# build manual page
pod2man = find_program('pod2man', native: true)
if pod2man.found()
  res = run_command(pod2man.full_path(), 'man/pcp.pod', 'pcp.1', check:true)
  if res.returncode() == 0
    install_man('pcp.1')
  endif
endif


subdir('tests')
