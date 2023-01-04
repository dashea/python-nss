# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup, Extension
import pkgconfig

nss_deps = pkgconfig.parse("nss")
nspr_deps = pkgconfig.parse("nspr")

nss_error_extension = Extension(
    "nss.error",
    sources=["src/py_nspr_error.c"],
    include_dirs=nss_deps["include_dirs"] + nspr_deps["include_dirs"] + ["src"],
    depends=["src/py_nspr_common.h", "src/py_nspr_error.h", "src/NSPRerrs.h", "src/SSLerrs.h", "src/SECerrs.h"],
    libraries=nspr_deps["libraries"],
)

nss_io_extension = Extension(
    "nss.io",
    sources=["src/py_nspr_io.c"],
    include_dirs=nss_deps["include_dirs"] + nspr_deps["include_dirs"] + ["src"],
    depends=["src/py_nspr_common.h", "src/py_nspr_error.h", "src/py_nspr_io.h"],
    libraries=nspr_deps["libraries"],
)

nss_nss_extension = Extension(
    "nss.nss",
    sources=["src/py_nss.c"],
    include_dirs=nss_deps["include_dirs"] + nspr_deps["include_dirs"] + ["src"],
    depends=["src/py_nspr_common.h", "src/py_nspr_error.h", "src/py_nss.h"],
    libraries=nspr_deps["libraries"] + nss_deps["libraries"],
)

nss_ssl_extension = Extension(
    "nss.ssl",
    sources=["src/py_ssl.c"],
    include_dirs=nss_deps["include_dirs"] + nspr_deps["include_dirs"] + ["src"],
    depends=["src/py_nspr_common.h", "src/py_nspr_error.h", "src/py_nspr_io.h", "src/py_ssl.h", "src/py_nss.h"],
    libraries=nspr_deps["libraries"] + nss_deps["libraries"],
)

setup(
    name="python-nss",
    package_dir={"nss": "nss"},
    packages=["nss"],
    ext_modules=[nss_error_extension, nss_io_extension, nss_nss_extension, nss_ssl_extension],
)
