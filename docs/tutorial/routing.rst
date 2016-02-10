Routing
-------
Buses have different routes in a city. Requests have different routes in a server too.
Different buses are identified by bus numbers. Different Requests are identified by Regex Expressions.

If you don't know what is regular expressions, please visit `Regular Expressions on Python Docs <https://docs.python.org/3/library/re.html>`_.

The simplest regular expression is just plain string, like ``/`` or ``/index.htm``.
We can add routes like ``@app.add_handler("/")`` or ``@app.add_handler("/index.htm")``,
but how about ``/posts/???.htm`` (??? can be any strings) that identifies posts in a blog system?

Let's look at the example below:

.. literalinclude:: ../../examples/routing.py
   :language: python3
   :lines: 17-


This example contains two types of dynamic routing example:

- Positional Match, like: ``(.*?)``.
- Keyword Match, like: ``(?P<name>.*?)``.

Theortically, all positional matches will be positional arguments passed to the method function,
and all keyword matches will be keyword arguments passed to the method function.

**However, all keyword matches also have a position in a regular expression.
Therefore, we recommend you to use keyword match.**
