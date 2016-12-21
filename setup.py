#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2016 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from setuptools import find_packages, setup

import pip
import sys

setup_requires = ["packaging>=16.5"]

try:
    import packaging

except ImportError:
    pip.main(["install"] + setup_requires)
    import packaging

if not sys.version_info[:3] >= (3, 5, 0):
    raise RuntimeError("FutureFinity requires Python 3.5.0 or higher.")

else:
    import futurefinity._version
    import futurefinity.testutils

install_requires = []
install_requires.extend(setup_requires)

full_requires = ["cryptography>=1.2,<2.0"]
full_requires.extend(install_requires)

tests_require = ["pytest>=3.0,<4.0"]
tests_require.extend(full_requires)

if __name__ == "__main__":
    setup(
        name="futurefinity",
        version=futurefinity._version.version,
        author="Futur Solo",
        author_email="futursolo@gmail.com",
        url="https://github.com/futursolo/futurefinity",
        license="Apache License 2.0",
        description="FutureFinity is an asynchronous Python web framework "
                    "designed for asyncio and native coroutines.",
        long_description=open("README.rst", "r").read(),
        packages=find_packages(),
        include_package_data=True,
        setup_requires=setup_requires,
        install_requires=install_requires,
        tests_require=tests_require,
        zip_safe=False,
        extras_require={
            "full": full_requires,
            "test": tests_require
        },
        cmdclass={
            "test": futurefinity.testutils.TestCommand
        },
        classifiers=[
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: MacOS",
            "Operating System :: MacOS :: MacOS X",
            "Operating System :: Microsoft",
            "Operating System :: Microsoft :: Windows",
            "Operating System :: POSIX",
            "Operating System :: POSIX :: Linux",
            "Operating System :: Unix",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3 :: Only",
            "Programming Language :: Python :: Implementation :: CPython"
        ]
    )
