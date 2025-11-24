# -*-python-*-

# genheader statictest buffertest sample pipetest decodertest

fs = import('fs')

binaries = [
    'gencheader',
    'statictest',
    'buffertest',
    'sample',
    'pipetest',
    'decodertest',
    'mangle',
    'invalidkeys',
    'pwhashes',
    'streamtest',
]

configs = [
    'cppunittests.cfg',
    'iotests.cfg',
    'jsonunittests.cfg',
    'keys.cfg',
    'pyunittests.cfg',
    'stresstests.cfg',
    'unittests.cfg',
    'md5',
    'jot',
    'bart.pub',
    'key-alicia-pub',
    'key-alicia-sec',
    'key-bobby-pub',
    'key-bobby-sec'
]

foreach binary: binaries
  executable(
    binary,
    binary + '.c',
    include_directories: [pcp_inc],
    dependencies: [libpcp_dep, pcp_deps],
   )
endforeach

foreach config: configs
  cp = fs.copyfile(config)
endforeach

unittest = find_program('unittests.sh', '.')

test('C tests', unittest, args : ['unittests.cfg'])
test('IO tests', unittest, args : ['iotests.cfg'])
test('JSON tests', unittest, args : ['jsonunittests.cfg'])
