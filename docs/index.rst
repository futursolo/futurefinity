FutureFinity |release| Documentation
========================================

.. highlight:: python3

Overview
--------
  FutureFinity is an asynchronous Python web framework designed for asyncio and native coroutines.
  Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
  at the same time.

  The Source Code is hosted on `GitHub <https://github.com/futursolo/futurefinity>`_,
  you can also submit issues through `GitHub Issues <https://github.com/futursolo/futurefinity/issues>`_.

Hello, World!
-------------

.. literalinclude:: ../examples/hello_world.py
   :language: python3
   :lines: 17-

Installation
------------

The installation of FutureFinity is as sample as install other applications through pip::

  pip install futurefinity

Install the latest GitHub Master Version::

  pip install git+git://github.com/futursolo/futurefinity.git

Install From Source Code:

Download :current_tarball:`z`::

  tar xvzf FutureFinity-(version).tar.gz
  cd FutureFinity-(version)
  python setup.py install

If this is not a stable release of FutureFinity, please do unittest before you use it::

  python setup.py test

If any tests failed, please report an issue on `GitHub <https://github.com/futursolo/futurefinity/issues/new>`_.

System Dependencies
-------------------
FutureFinity |version| will only work on Python 3.5 or higher.

**Required**:

* `Routes <https://pypi.python.org/pypi/Routes>`_ is the routing system
  currently used by FutureFinity.

**Optional**:

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
   utils


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
