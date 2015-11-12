FutureFinity |release| Documentation
========================================

Overview
--------
  FutureFinity is an asynchronous web framework, using asyncio, inspired by Tornado and Flask.
  Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
  at the same time.

Hello, World!
-------------

.. parsed-literal::
  import futurefinity.web
  import asyncio

  loop = asyncio.get_event_loop()
  app = futurefinity.web.Application()

  @app.add_handler("/")
  class RootHandler:
      async def get(self, *args, **kwargs):
          return "Hello, World!"

  app.listen(23333)

  try:
      loop.run_forever()
  except KeyboardInterrupt:
      pass


.. toctree::
   :titlesonly:

   install
   web


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
