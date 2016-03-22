FutureFinity |release| Documentation
====================================

.. highlight:: python3

Overview
--------
  FutureFinity is an asynchronous Python web framework designed for asyncio and native coroutines.
  Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
  at the same time.

  The Source Code is hosted on `GitHub <https://github.com/futursolo/futurefinity>`_.

Hello, World!
-------------

.. literalinclude:: ../examples/hello_world.py
   :language: python3
   :lines: 17-

Installation
------------

The installation of FutureFinity is as sample as install other applications through pip::

  pip install futurefinity

Install from GitHub master branch::

  pip install git+git://github.com/futursolo/futurefinity.git

Install from source code:

Download :current_tarball:`z`::

  tar xvzf futurefinity-(version).tar.gz
  cd futurefinity-(version)
  python setup.py install

If this is not a stable release of FutureFinity, please do unittest before you use it::

  python setup.py test

If any tests failed, please report an issue.

System Dependencies
-------------------
FutureFinity |version| will only work on Python 3.5 or higher.

**Optional Dependencies**:

* `Cryptograhy <https://pypi.python.org/pypi/cryptography/>`_ is the crypto library
  currently used by FutureFinity's security features.

* `Jinja2 <https://pypi.python.org/pypi/cryptography/>`_ is the template library
  currently used by FutureFinity's template rendering.

**Platform**:

Theoretically, FutureFinity can run on any system that supports asyncio.
However, asyncio.SelectorEventLoop has a really low performance on windows
and cannot handle over 512 handlers at the same time, and asyncio.ProactorEventLoop
cannot support many features of asyncio. We recommend that running FutureFinity
on Windows for only development use.

Also see:
---------
.. toctree::
   :titlesonly:

   tutorial
   web
   server
   client
   protocol
   routing
   security
   template
   utils


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
