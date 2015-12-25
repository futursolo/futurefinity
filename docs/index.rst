FutureFinity |release| Documentation
========================================

.. highlight:: python3

.. image:: https://travis-ci.org/futursolo/FutureFinity.svg?branch=master
    :target: https://travis-ci.org/futursolo/FutureFinity

.. image:: https://coveralls.io/repos/futursolo/FutureFinity/badge.svg?branch=master&service=github
    :target: https://coveralls.io/github/futursolo/FutureFinity?branch=master

.. image:: https://img.shields.io/pypi/v/FutureFinity.svg?style=flat
    :target: https://pypi.python.org/pypi/FutureFinity

.. image:: https://img.shields.io/github/license/futursolo/FutureFinity.svg
    :target: https://github.com/futursolo/FutureFinity/blob/master/LICENSE

.. image:: https://img.shields.io/pypi/pyversions/FutureFinity.svg
    :target: https://www.python.org/downloads/release/python-350/


Overview
--------
  FutureFinity is an asynchronous Python web framework designed for asyncio and native coroutines.
  Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
  at the same time.

Hello, World!
-------------

.. literalinclude:: ../example/hello_world.py
   :language: python3
   :lines: 17-

Installation
------------

The installation of FutureFinity is as sample as install other applications thourgh pip::

  pip install FutureFinity

For system requirements and other installation method, please read :doc:`install`.

Tutorial
--------
Based on the "Hello, World!" example, we can add more exciting features to it.

Dynamic Routing:

.. literalinclude:: ../example/dynamic_routing.py
   :language: python3
   :lines: 24-28

Custom HTTP Header:

.. literalinclude:: ../example/custom_header.py
   :language: python3
   :lines: 24-33

User Cookie:

.. literalinclude:: ../example/user_cookie.py
   :language: python3
   :lines: 25-31

Link argument(s), Body argument(s), and UTF-8 support:

.. literalinclude:: ../example/link_arg_body_arg_and_utf8.py
   :language: python3
   :lines: 25-37

Also see:
---------
.. toctree::
   :titlesonly:

   install
   web
   server
   utils
   interface


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
