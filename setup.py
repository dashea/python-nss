# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os.path
import codecs

import pkgconfig

from distutils.core import setup, Extension

def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()

def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")

name = 'python-nss'
version = get_version('src/__init__.py')
release = version

#------------------------------------------------------------------------------

def main(argv):

    with open('README') as f:
        long_description = f.read()

    debug_compile_args = ['-O0', '-g']
    extra_compile_args = []
    include_roots = []

    for arg in argv[:]:
        if arg in ('--debug', ):
            print("compiling with debug")
            extra_compile_args += debug_compile_args
            argv.remove(arg)
        if arg in ('-t', '--trace'):
            print("compiling with trace")
            extra_compile_args += ['-DDEBUG']
            argv.remove(arg)
        if arg.startswith('--include-root'):
            include_roots.append(arg.split('--include-root=')[1])
            argv.remove(arg)

    nss_deps = pkgconfig.parse('nss')
    nspr_deps = pkgconfig.parse('nspr')

    nss_error_extension = \
        Extension('nss.error',
                  sources            = ['src/py_nspr_error.c'],
                  include_dirs       = nss_deps['include_dirs'] + nspr_deps['include_dirs'],
                  depends            = ['src/py_nspr_common.h', 'src/py_nspr_error.h',
                                         'src/NSPRerrs.h', 'src/SSLerrs.h', 'src/SECerrs.h'],
                  libraries          = nspr_deps['libraries'],
                  extra_compile_args = extra_compile_args,
                  )

    nss_io_extension = \
        Extension('nss.io',
                  sources            = ['src/py_nspr_io.c'],
                  include_dirs       = nss_deps['include_dirs'] + nspr_deps['include_dirs'],
                  depends            = ['src/py_nspr_common.h', 'src/py_nspr_error.h', 'src/py_nspr_io.h'],
                  libraries          = nspr_deps['libraries'],
                  extra_compile_args = extra_compile_args,
                  )

    nss_nss_extension = \
        Extension('nss.nss',
                  sources            = ['src/py_nss.c'],
                  include_dirs       = nss_deps['include_dirs'] + nspr_deps['include_dirs'],
                  depends            = ['src/py_nspr_common.h', 'src/py_nspr_error.h', 'src/py_nss.h'],
                  libraries          = nspr_deps['libraries'] + nss_deps['libraries'],
                  extra_compile_args = extra_compile_args,
                  )

    nss_ssl_extension = \
        Extension('nss.ssl',
                  sources            = ['src/py_ssl.c'],
                  include_dirs       = nss_deps['include_dirs'] + nspr_deps['include_dirs'],
                  depends            = ['src/py_nspr_common.h', 'src/py_nspr_error.h', 'src/py_nspr_io.h',
                                        'src/py_ssl.h', 'src/py_nss.h'],
                  libraries          = nspr_deps['libraries'],
                  extra_compile_args = extra_compile_args,
                  )

          #bug_tracker       = 'https://bugzilla.redhat.com/buglist.cgi?submit&component=python-nss&product=Fedora&classification=Fedora'
          #bug_enter     = 'https://bugzilla.redhat.com/enter_bug.cgi?component=python-nss&product=Fedora&classification=Fedora',
    setup(name             = name,
          version          = version,
          description      = 'Python bindings for Network Security Services (NSS) and Netscape Portable Runtime (NSPR)',
          long_description = long_description,
          author           = 'John Dennis',
          author_email     = 'jdennis@redhat.com',
          maintainer       = 'John Dennis',
          maintainer_email = 'jdennis@redhat.com',
          license          = 'MPLv2.0 or GPLv2+ or LGPLv2+',
          platforms        = 'posix',
          url              = 'http://www.mozilla.org/projects/security/pki/python-nss',
          download_url     = '',
          ext_modules      = [nss_error_extension,
                              nss_io_extension,
                              nss_nss_extension,
                              nss_ssl_extension,
                             ],
          package_dir      = {'nss':'src'},
          packages         = ['nss'],
    )

    return 0

#------------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main(sys.argv))
