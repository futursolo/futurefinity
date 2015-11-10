System Requirements/Install FutureFinity
========================================

**System Requirements**:
FutureFinity |version| will only work on Python 3.5 or higher.

* `Routes <https://pypi.python.org/pypi/Routes>`_ is the routing system
  currently used by FutureFinity.

**Platform**:
  Theoretically, FutureFinity can run on any system that supports asyncio.
  However, asyncio.SelectorEventLoop has a really low performance on windows
  and cannot handle over 512 handlers at the same time, and asyncio.ProactorEventLoop
  cannot support many features of asyncio. We recommend that running FutureFinity
  on Windows for only development use.

**Installation**:

Get the lasest FutureFinity release from `PyPI <https://pypi.python.org/pypi/futurefinity>`_ using pip(**Recommended**)::

  pip install futurefinity

Install the latest GitHub Master Version::

  pip install git+git://github.com/futursolo/futurefinity.git

Install From Source Code:

Download :current_tarball:`z`:

.. parsed-literal::

  tar xvzf futurefinity-|version|.tar.gz
  cd futurefinity-|version|
  python setup.py build
  python setup.py install

If this is not a stable release of FutureFinity, please do unittest before you use it::

  python setup.py test

If any tests failed, please report an issue on `GitHub <https://github.com/futursolo/FutureFinity/issues/new>`_.
