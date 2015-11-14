#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

install_requires = ["routes"]

tests_require = ["requests", "nose2", "jinja2"]

if __name__ == "__main__":
    setup(
        name="FutureFinity",
        version="0.0.1",
        author="Futur Solo",
        author_email="futursolo@gmail.com",
        url="https://finity.futures.moe/",
        license="http://www.apache.org/licenses/LICENSE-2.0",
        description="FutureFinity is a fantastic Python web framework, "
                    "using asyncio, inspired by Tornado and Flask.",
        packages=["futurefinity"],
        test_suite="nose2.collector.collector",
        install_requires=install_requires,
        tests_require=tests_require,
        zip_safe=False,
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
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3 :: Only",
            "Programming Language :: Python :: Implementation :: CPython"
        ]
    )
