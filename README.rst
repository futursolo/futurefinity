FutureFinity
============
FutureFinity is an asynchronous Python web framework, using asyncio, inspired by Tornado and Flask.

.. image:: https://travis-ci.org/futursolo/FutureFinity.svg?branch=master
    :target: https://travis-ci.org/futursolo/FutureFinity

Documentation
-------------
Documentation for latest stable version is hosted on `https://finity.futures.moe <https://finity.futures.moe>`_.

For development version or deprecated version, download or clone the source,
and do `cd doc; make html`.

Requirements
------------
- Python>=3.5.0
- Routes>=2.0.0
- Cryptography>=1.0.0(Optional, Recommended, Used by AES_GCM Secure Cookie)
- Jinja2>=2.0.0(Optional, Used by Template Rendering)

Installation
------------

.. code-block:: shell

  $ pip install FutureFinity

License
-------
Copyright 2015 Futur Solo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
