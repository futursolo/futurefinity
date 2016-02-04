Get Started
-----------
FutureFinity is an asynchronous Python web framework designed for asyncio and native coroutines.
Benefit from the non-blocking model and asyncio, FutureFinity can handle thousands of requests
at the same time.

Let's look at the ``Hello, World!``.

.. literalinclude:: ../../examples/hello_world.py
   :language: python3
   :lines: 17-

We have seen that ``Hello, World!`` example on the index of the documentation.
It looks pretty easy, but some parts look like quite strange.
Let's divide them up step-by-step.

At the beginning of the example, there are two imports, which are
``futurefinity.web`` and ``asyncio``. ``futurefinity.web`` is the core part when
FutureFinity works as a Web Framework. ``asyncio`` is an asynchronous library
included in Python as a standard library since Python 3.4.
FutureFinity uses the EventLoop and TCP Protocol of ``asyncio``.

For more information of ``asyncio``, please visit `asyncio on Python Docs <https://docs.python.org/3/library/asyncio.html>`_.

Next line, ``app = futurefinity.web.Application()`` is going to create an instance
of Application class. The duty of Application class is to create server,
store all handlers, and handle request to right ``RequestHandler``.

Let's move to the class.

.. code-block:: python3

   @app.add_handler("/")
   class RootHandler(futurefinity.web.RequestHandler):
       async def get(self, *args, **kwargs):
           return "Hello, World!"

Unlike Flask or Bottle, which use functions as request handlers, FutureFinity uses
inherit classes from ``futurefinity.web.RequestHandler`` to handle requests.
To specify the method to handle, please override the method as shown above.
The returned string/bytes will be the body content. All methods should use a
``async def`` keyword instead of ``def`` to indicate that this is a coroutine function,
not a normal function, which gives you the ability to use ``await`` statement in the function.
On the top of the class, there is a ``@app.add_handler("/")``.
``@`` means that this is a decorator. The class or function below is decorated by the decorator.
When the script is interpreted, the decorator is executed first,
and the function or class is decorated at that time.
Then when the function or class is executed or instanced,
the decorated one will be executed or instanced.

For more information about ``async`` and ``await`` statement, please visit `asyncio Tasks and Coroutines on Python Docs <https://docs.python.org/3/library/asyncio-task.html>`_.

For more information about ``@`` decorator, please visit `decorator on Python Docs <https://docs.python.org/3/glossary.html#term-decorator>`_.

``asyncio.get_event_loop().run_forever()`` is to get the event loop from asyncio and start it.

These are the basis of a minimal FutureFinity Application.
