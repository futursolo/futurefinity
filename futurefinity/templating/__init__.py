#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2016 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
FutureFinity Templating.

FutureFinity Templating is a template with the `async`/`await`
statement support.

In the early stage, I had considered to select one of the
well-known templating systems as the default templating system of FutureFinity,
however, all of them lacked the asynchronous support, which is the core,
and the most important design philosophy of FutureFinity. Finally, I decided
to write a new templating system for FutureFinity.

A Simple Example:
-----------------

.. code-block:: python3
    <!DOCTYPE>
    <html>
        <head>
            <title><%= await handler.get_page_title() %></title>
        </head>
        <body>
            <main>
                <% async for item in db.items.find() %>
                    <article>
                        <div class="title"><%= item["title"] %></div>
                        <div class="author"><%= item["author"] %></div>
                        <div class="content"><%= item["content"] %></div>
                    </article>
                <% end %>
            </main>
        </body>
    </html>

It looks quite similar to the Python syntax. Actually, the templating system
rewrites the template string into the Python code, and ask the interpreter to
"compile" the plain Python code into Python byte code.

Technically, You can use any Python syntax in the template but with some
changes:

1. All the python style syntax is wrapped between `<%` and `%>`.
2. Indent Is not indicated by `:` any more, but recognised by the Templating
  system automatically. To unident such a indentation,
  use a special `end` statement.
3. print function still prints to the console on the server side, to output
  to the template, use `=` or other output statements.

Syntax
------
The syntax of FutureFinity Templating is highly inspired by `tornado.template`,
Jinja2 and mako. So maybe you can find some similarities and differences among
them and FutureFinity Templating.

1. Output Statement
    The simplest and the most common-used(perhaps) statement in the whole
    Templating System.

    .. code-block: python3
        Hello, <%= user.name %>.

    `=` is the statement keyword, and everything after that between `<%` and
    `%>` will be evaluated by the Python interpreter. Also, since the template
    is wrapped by a native coroutine function, `async`/`await` statement will
    just work as usual inside any statement if they make sense under Python
    syntax. This means, you can also write your code like:

    .. code-block: python3
        Hello, <%= await user.get_user_name() %>.

    And `async` statement modifier will be covered later in this documentation.

    The result passed to `=` will be escaped by the default escape function,
    which is `self.escape_html` in the namespace by default, you can
    change it in the :class:`.TemplateLoader` or :class:`.Template` arguments
    or in the runtime which will be discussed later. There're also other
    escape functions:

    1. `r=` or `raw=` points to `self.no_escape` in the namespace which only
        ensures that the output is string.
    2. `h=` or `html=` points to `self.escape_html` in the namespace which
        escape string in a html safe way.
    3. `j=` or `json=` points to `self.escape_json` in the namespace which
        escape string in a json safe way.
    4. `u=` or `url=` points to `self.escape_url` in the namespace which
        escape string in a url safe way. You can define if you want to escape
        the space by plus mark or not by the :class:`.TemplateLoader` or
        :class:`.Template` arguments or in the runtime which will be discussed
        later.

2. Indent Statment
    statements require an indent in the Python syntax is called an indent
    statement.

    For example:

    .. code-block:: python3
        if a == b:
            print("They are the same.")

    Which is equivalent to the code below in FutureFinity Templating:

    .. code-block:: python3
        <% if a == b %>
            <%= "They are the same." %>
        <% end %>

    As we discussed before, In FutureFinity Templating, `:` does not indicate
    the indentation any more. The templating system will deal with that
    automatically. However, you still need to unident the indentation manually
    using an unindent statement or a half indent statement which will be
    discussed later.

    Keywords: `if`, `with`, `for`, `while`, and `try`.

    `async` statement modifier will work on `for` and `with`, which means that
    you can write::

        <% async for item in db.find() %>
            <%= item.content %>
        <% end %>

3. Unindent Statement
    The statement unindent an Python indentation is call an unindent statement.

    Example:

    .. code-block:: python3
        <% if a == b %>
            <%= "They are the same." %>
        <% end %>

    The `if` statement creates an indentation in the generated Python code, to
    finish the indentation, you may use a special `end` statement like the
    example above. However, redundant unindent statement will raise an
    `ParseError`.

    This works for any indent statements.

4. Half-Indent Statement
    The Statement unindent the last indentation and establish a new indentation
    at the same time.

    Example:

    .. code-block:: python3
        <% if a == b %>
            <%= "They are the same." %>
        <% else %>
            <%= "They are not the same." %>
        <% end %>

    The `if` statement creates an indenation as discussed above, and the
    `else` statement will automatically unident the `if` statement, and
    establish an new indentation until another unindent statement or
    half-indent statement is reached.

    Keywords: `else`, `elif`, `except`, and `finally`.

5. Comment statement
    The Statement contains the comments that will be removed from the
    rendering result.

    .. code-block:: python3
        This is the content.
        <%# This is the comment. %>

    When the template string is being parsed, the comment will be removed from,
    the output. The result of the example above is:

    .. code-block:: python3
        This is the content.

6. Include Statement
    The statement includes a another template file into the current template.

    Example:

    `header.html`:
    .. code-block:: python3
        <header>
            <h1>Site Title</h1>
        </header>

    `main.html`:
    .. code-block:: python3
        <html>
            <head>
                <title>Main Page</title>
            </head>
            <body>
                <% include "header.html" %>
                <main>
                    <p>Thank you for visiting.</p>
                </main>
            </body>
        </html>

    When `main.html` being rendered, it will ask the loader to load
    `header.html` and render `header.html` **at the runtime**,
    then append it to the result of `main.html`. The result of the example
    above is:

    .. code-block:: python3
        <html>
            <head>
                <title>Main Page</title>
            </head>
            <body>
                <header>
                    <h1>Site Title</h1>
                </header>
                <main>
                    <p>Thank you for visiting.</p>
                </main>
            </body>
        </html>

7. Inherit statement
    The statement inherits the current template from another template.

    Example:

    `layout.html`:
    .. code-block:: python3
        <html>
            <head>
                <title><% block title %><% end %></title>
                <% block head %><% end %>
            </head>
            <body>
                <%r= self.child_body %>
            </body>
        </html>

    `main.html`:
    .. code-block:: python3
        <% inherit "main.html" %>
        <% block title %>Main Page<% end %>
        <main>
            <p>Thank you for visiting.</p>
        </main>

    When `main.html` being rendered, it will ask the loader to load
    `layout.html` and update all the blocks in `layout.html` with the blocks in
    `main.html`. The other content outside the blocks in `main.html` can be
    accessed using `self.child_body` in `layout.html`. **When outputting the
    `self.child_body`, make sure to use `r=` or `raw=` output statement, or the
    output will be escaped.** The result of the example above is:

    .. code-block:: python3
        <html>
            <head>
                <title>Main Page</title>
            </head>
            <body>
                <main>
            <p>Thank you for visiting.</p>
        </main>
            </body>
        </html>

8. Inline statement
    The Statement represents a Python inline keyword.

    Example:

    `layout.html`:
    .. code-block:: python3
        <% from time import time as get_timestamp %>
        <% import random %>

        <% while True %>
            <%r= str(get_timestamp()) %>
            <% if random.choice(range(0, 2)) %>
                <% break %>
            <% end %>
        <% end %>

    This example will print time stamps until a True value is selected by
    random module.

    Keywords: `break`, `continue`, `import`, and `raise`.

9. Code statement
    The statement executes arbitrary **inline** code in your template.

    .. code-block:: python3
        <%@ a = "Hello" %>
        <%r= a %>
        <%@ a += ", world!"%>
        <%r= a %>

    This prints:

    .. code-block:: python3
        Hello
        Hello, world!

10. Template begin and end mark escaping
    In the template, `<%%` escapes `<%`, and `%%>` escapes `%>`. It may only
    take effect where `<%` or `%>` has actual meaning.

    Example:

    .. code-block:: python3
        <%% is the begin mark, and <%r= \"%%> is the end mark. \" %>
        <%r= \"<% and\" %> %> only need to be escaped whenever they
        have ambiguity of the templating system.

    This prints:

    .. code-block:: python3
        <% is the begin mark, and %> is the end mark.
        <% and %> only need to be escaped whenever they
        have ambiguity of the templating system.
"""
from .utils import *

from .template import Template
from .statement import Statement
from .loader import TemplateLoader

from . import utils
from . import loader
from . import parser
from . import printer
from . import template
from . import namespace
