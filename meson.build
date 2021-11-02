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
conf.set_quoted('LIBDIR', libdir)
conf.set_quoted('SYSCONFDIR', sysconfdir)
conf.set_quoted('CLIENT', client_exe)
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

  test_1 = executable('test_1',
    'hello_world.c',
    c_args: ['-nostdlib', '-nostartfiles', '-shared'],
    link_args: ['-nostdlib', '-nostartfiles', '-shared'],
    pie: true,
  )

  gen = meson.source_root() / 'generator.py'
  test_profile = 'TEST'
  test_profile_dir = meson.build_root() / 'tests'
  mytarget = custom_target('targetname',
    output: test_profile,
    input: test_1,
    build_by_default: true,
    capture: true,
    command: [gen, '@BUILD_ROOT@/@INPUT@']
    )
endif

test_2 = executable('test_2',
  'ld-so-server.c',
  dependencies: [libsystemd, libselinux],
  c_args: ['-DPROFILE_DIR="."', '-DFORCE_UNIT="TEST"']
)

