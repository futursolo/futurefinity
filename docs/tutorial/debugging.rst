Debugging
---------
Debugging is important, since everyone will make mistakes. Python has
perfect traceback to help you find the problem. However, for asynchronous program,
debugging has been divided into two levels -- the application level and the eventloop
level.

Here's a simple example of debugging:

.. literalinclude:: ../../examples/debugging.py
   :language: python3
   :lines: 17-

For most cases, the bug comes from the application, you can just turn on the application level
debugging by passing ``debug=True`` to Application Class as a keyword argument.

For some rare situations, which means the FutureFinity itself may have bugs,
we can use eventloop level debugging by executing ``asyncio.gen_event_loop().set_debug(True)``
before the eventloop starts.

You've finished this simple tutorial; however, this is not an end, this is a new start.
You can see the rest of the documentation to comprehend FutureFinity deeper, or
just write a simple application.
