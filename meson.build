# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

project('ld-so-daemon',
  'c',
  version: '0.0.0-alpha',
  meson_version: '>=0.52.1',
  license: ['LGPL-2.1-or-later', 'BSD-3-Clause'],
)

conf = configuration_data()
prefixdir = get_option('prefix')
libdir = prefixdir / 'lib'
sysconfdir = prefixdir / get_option('sysconfdir')
client_exe = 'ld-so-client'
client_path = prefixdir / 'lib' / client_exe
conf.set_quoted('LIBDIR', libdir)
conf.set_quoted('SYSCONFDIR', sysconfdir)
conf.set_quoted('CLIENT', client_path)
config_h = configure_file(
  output: 'config.h',
  configuration: conf)

libsystemd = dependency('libsystemd')
libselinux = dependency('libselinux')
server = executable('ld-so-server',
  'ld-so-server.c',
  dependencies: [libsystemd, libselinux],
  install: true,
)

if get_option('b_coverage') != true
  client = executable(client_exe,
    'ld-so-client.c',
    c_args: ['-nostdlib', '-nostartfiles', '-shared'],
    link_args: ['-nostdlib', '-nostartfiles', '-shared'],
    install: true,
    pie: true,
  )

  test_1_lib = shared_library('test_1_lib',
    'hello_world_lib.c',
    c_args: ['-nostdlib', '-nostartfiles', '-shared', '-fPIC'],
    link_args: ['-nostdlib', '-nostartfiles', '-shared', '-fPIC'],
  )

  test_1 = executable('test_1',
    'hello_world.c',
    link_with: test_1_lib,
    c_args: ['-nostdlib', '-nostartfiles', '-shared', '-fPIC'],
    link_args: ['-nostdlib', '-nostartfiles', '-shared', '-fPIC'],
    pie: true,
  )

  gen = meson.source_root() / 'generator.py'
  test_profile = 'TEST'
  mytarget = custom_target('targetname',
    output: test_profile,
    input: test_1,
    build_by_default: true,
    capture: true,
    command: [gen, '@0@/test_1'.format(meson.build_root())]
    )
endif

test_2 = executable('test_2',
  'ld-so-server.c',
  dependencies: [libsystemd, libselinux],
  c_args: [
    '-DPROFILE_DIR="."',
    '-DFORCE_UNIT="@0@/TEST"'.format(meson.build_root()),
    '-DFORCE_CLIENT="@0@"'.format(meson.build_root() / client_exe)
  ]
)
