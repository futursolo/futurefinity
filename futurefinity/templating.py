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

from .utils import cached_property
from . import compat
from . import ioutils
from . import encoding
from typing import Optional, AnyStr, Union, Sequence, Mapping, Any, Callable
from types import CodeType

import io
import os
import re
import asyncio
import functools
import threading
import concurrent.futures

__all__ = ["TemplateNotFoundError", "ParseError", "InvalidStatementOperation",
           "PrinterError", "CodeGenerationError", "TemplateRenderError",
           "TemplateContext", "BlockAttrs", "Namespace",
           "CodePrinter", "Template", "BaseLoader", "AsyncFileSystemLoader"]

_BEGIN_MARK = "<%"
_END_MARK = "%>"
_ESCAPE_MARK = "%"

_ALLOWED_BLOCK_NAME = re.compile(r"^[a-zA-Z]([a-zA-Z0-9\_]+)?$")


class TemplateNotFoundError(FileNotFoundError):
    """
    Error when trying to load a template but the loader cannot find it.
    """
    pass


class ParseError(Exception):
    """
    Error when parsing template.
    """
    pass


class InvalidStatementOperation(Exception):
    """
    Error when performing the statement operation.
    """
    pass


class PrinterError(Exception):
    """
    Unspecific Error inside the Code Printer.
    """
    pass


class CodeGenerationError(Exception):
    """
    Error when Generating the Python code.
    """
    pass


class TemplateRenderError(Exception):
    """
    Error during renderring the template.
    """
    pass


class _ReadFinished(Exception):
    pass


class TemplateContext:
    def __init__(
        self, *, cache_tpls: bool=True, default_escape: compat.Text="html",
        input_encoding: str="utf-8", output_encoding: str="utf-8",
        escape_url_with_plus: bool=True,
            loop: Optional[asyncio.BaseEventLoop]=None):

        self._loop = loop or asyncio.get_event_loop()

        self._default_escape = default_escape
        self._input_encoding = input_encoding
        self._output_encoding = output_encoding
        self._escape_url_with_plus = escape_url_with_plus

        self._cache_tpls = cache_tpls

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop

    @property
    def default_escape(self) -> bool:
        return self._default_escape

    @property
    def input_encoding(self) -> bool:
        return self._input_encoding

    @property
    def output_encoding(self) -> bool:
        return self.output_encoding

    @property
    def escape_url_with_plus(self) -> bool:
        return self._escape_url_with_plus

    @property
    def cache_tpls(self) -> bool:
        return self._cache_tpls


class BlockAttrs:
    """
    Read all the blocks from the current namespace.
    """
    def __init__(self, namespace: "Namespace"):
        self.__dict__["_namespace"] = namespace

    def __getattr__(self, name: compat.Text) -> Callable[[], compat.Text]:
        if name in self._namespace._updated_block_fns.keys():
            block_fn = self._namespace._updated_block_fns[name]

        elif name not in self._namespace._tpl._root._blocks.keys():
            raise TemplateRenderError from KeyError(
                "Unknown Block Name {}.".format(name))

        else:
            block_fn = getattr(
                self._namespace, "_render_block_{}_str".format(name))

        async def wrapper(_defined_here=False):
            if _defined_here and self._namespace._parent is not None:
                return ""

            return await functools.partial(block_fn, self=self._namespace)()

        return wrapper

    def __setattr__(self, name: compat.Text, value: Any):  # pragma: no cover
        raise NotImplementedError

    __getitem__ = __getattr__
    __setitem__ = __setattr__


def _no_escape(var: compat.Text) -> compat.Text:
    return var


class Namespace:
    _escape_types = {
        "html":  encoding.escape_html,
        "json": encoding.escape_json,
        "url": encoding.escape_url,
        "raw": _no_escape,
    }

    def __init__(
            self, tpl: "Template", tpl_globals: Mapping[compat.Text, Any]):
        self._tpl = tpl
        self._context = self._tpl._context
        self._tpl_globals = tpl_globals

        self._finished = False
        self._parent = None

        self.__tpl_result__ = ""

        self._child_body = None

        self._updated_block_fns = {}

        self._escape_url_with_plus = self._context.escape_url_with_plus
        self._default_escape = self._context.default_escape

    @property
    def default_escape(self) -> Callable[[compat.Text], compat.Text]:
        """
        Return the default escape function.
        """
        return self._escape_types[self._default_escape]

    @default_escape.setter
    def default_escape(self, default_type: compat.Text):
        """
        Set the default escape function.
        """
        if default_type not in self._escape_types.keys():
            raise TemplateRenderError(
                ("Unknown escape type,"
                 "expecting one of {}, got: {}")
                .format(self._escape_types.keys(), default_type))

        self._default_escape = default_type

    @property
    def escape_url_with_plus(self) -> bool:
        return self._escape_url_with_plus

    @escape_url_with_plus.setter
    def escape_url_with_plus(self, value: bool):
        assert isinstance(value, bool), \
            "escape_url_with_plus property can only take boolean value."

        self._escape_url_with_plus = value

    @property
    def child_body(self) -> compat.Text:
        """
        Return the body from the child template.
        """
        assert self._child_body is not None, "There's no child body."
        return self._child_body

    @property
    def blocks(self) -> Mapping:
        """
        Return the block selector.
        """
        return BlockAttrs(self)

    @property
    def parent(self) -> "Namespace":
        """
        Return the parent of the current template.
        """
        assert self._parent is not None, "Parent is not set."
        return self._parent

    @property
    def _tpl_result(self) -> compat.Text:
        assert self._finished, "Renderring has not been finished."
        return self.__tpl_result__

    @property
    def _loader(self) -> "BaseLoader":
        return self._tpl._loader

    def _get_globals(self) -> Mapping[compat.Text, Any]:
        new_globals = {}

        new_globals.update(self._tpl_globals)

        if "_TplCurrentNamespace" in new_globals.keys():
            del new_globals["_TplCurrentNamespace"]

        return new_globals

    def _update_blocks(self, **kwargs):
        self._updated_block_fns.update(**kwargs)

    def _update_child_body(self, child_body: compat.Text):
        assert self._child_body is None, "There's already a child body."
        self._child_body = child_body

    async def _inherit_tpl(self):  # Need to be Changed.
        if self._parent is None:
            return

        self._parent._update_child_body(self.__tpl_result__)

        block_fns = {}

        for key in self._tpl._root._blocks.keys():
            block_fns[key] = getattr(self, "_render_block_{}_str".format(key))

        block_fns.update(**self._updated_block_fns)

        self._parent._update_blocks(**block_fns)

        await self._parent._render()

        self.__tpl_result__ = self._parent._tpl_result

    async def _add_parent(self, path: compat.Text):
        assert self._parent is None, \
            "A template can only inherit from one parent template."

        parent_tpl = await self._loader.load_tpl(
            path, origin_path=self._tpl._path)

        self._parent = parent_tpl._get_namespace(
            tpl_globals=self._get_globals())

    async def _include_tpl(self, path: compat.Text) -> compat.Text:
        tpl = await self._loader.load_tpl(path, origin_path=self._tpl._path)

        tpl_namespace = tpl._get_namespace(self._get_globals())

        await tpl_namespace._render()
        return tpl_namespace._tpl_result

    async def _render_body_str(self) -> compat.Text:  # pragma: no cover
        raise NotImplementedError

    async def _render(self):
        assert not self._finished, "Renderring has already been finished."
        self.__tpl_result__ = await self._render_body_str()

        await self._inherit_tpl()
        self._finished = True


class CodePrinter:
    """
    Print Python code with indent gracefully.
    """
    def __init__(
        self, path: compat.Text="<string>",
            end: compat.Text="\n", indent_mark: compat.Text="    "):
        self._path = path
        self._indent_num = 0
        self._committed_code = ""

        self._end = end
        self._indent_mark = indent_mark

        self._finished = False

    def writeline(self, line: compat.Text):
        """
        Write a line with indent.
        """
        assert not self._finished, "Code Generation has already been finished."

        final_line = self._indent_mark * self._indent_num + line + self._end
        self._committed_code += final_line

    def writelines(self, lines: Sequence[compat.Text]):
        for line in lines:
            self.writeline(line)

    def code_indent(self) -> "CodePrinter":
        """
        Indent the code with `with` statement.

        Example:
        ..code-block:: python3

            printer.print_line("def a():")
            with printer.code_indent():
                printer.print_line("return \"Text from function a.\"")

            printer.print_line("a()")
        """
        assert not self._finished, "Code Generation has already been finished."
        return self

    def _inc_indent_num(self):
        assert not self._finished, "Code Generation has already been finished."
        self._indent_num += 1

    def _dec_indent_num(self):
        assert not self._finished, "Code Generation has already been finished."
        self._indent_num -= 1

    def __enter__(self):
        self._inc_indent_num()

    def __exit__(self, *exc):
        self._dec_indent_num()

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def plain_code(self) -> compat.Text:
        """
        Return the plain, printed code.
        """
        self._finished = True
        return self._committed_code

    @cached_property
    def compiled_code(self) -> CodeType:
        """
        Return the compiled code.
        """
        return compile(self.plain_code, self._path, "exec", dont_inherit=True)


class _Statement:
    _keywords = ()

    def __init__(
        self, keyword: Optional[compat.Text]=None,
        rest: Optional[compat.Text]=None,
            comment: Optional[compat.Text]=None):
        self._keyword = keyword
        self._rest = rest

        self._statements = []

        self._comment = comment

        self._should_indent = False
        self._should_append = True
        self._should_unindent = False

        self._finished = False

    def append_statement(self, statement: "Statement"):
        """
        Append a statement to the current statement.
        """
        assert not self._finished, "This statement has already been finished."
        assert self.should_indent, \
            "This statement is not an indent statement."

        self._statements.append(statement)

    def unindent(self):
        """
        Unindent a statement.
        """
        assert not self._finished, "This statement has already been finished."
        assert self.should_indent, \
            "This statement is not an indent statement."

        self._finished = True

    @property
    def should_indent(self) -> bool:
        return self._should_indent

    @property
    def should_append(self) -> bool:
        return self._should_append

    @property
    def should_unindent(self) -> bool:
        return self._should_unindent

    def _raise_invalid_operation(
        self, message: compat.Text,
            from_err: Optional[BaseException]=None):
        err_str = "{} {}.".format(
            message.strip(), (self._comment.strip() or ""))

        if from_err:
            raise InvalidStatementOperation(err_str) from from_err

        else:
            raise InvalidStatementOperation(err_str)

    def _raise_code_gen_error(self, message: compat.Text,
                              from_err: Optional[BaseException]=None):
        err_str = "{} {}.".format(
            message.strip(), (self._comment.strip() or ""))

        if from_err:
            raise CodeGenerationError(err_str) from from_err
        else:
            raise CodeGenerationError(err_str)

    def _print_code_impl(self, printer: CodePrinter):  # pragma: no cover
        raise NotImplementedError(
            "print code in this statement is not implemented.")

    def print_code(self, printer: CodePrinter):
        try:
            self._print_code_impl(printer)

        except Exception as e:
            self._raise_code_gen_error(
                "Error occurred during code generation",
                from_err=e)

    @property
    def statement_str(self) -> compat.Text:
        """
        Generate the statement string.
        """
        return "{} {}".format(self._keyword, (self._rest or "")).strip()

    def _writeline_with_comment(
            self, printer: "CodePrinter", line: compat.Text):
        printer.writeline(line + "  # " + self._comment)

    def _writelines_with_comment(
            self, printer: "CodePrinter", lines: Sequence[compat.Text]):
        for line in lines:
            self._writeline_with_comment(printer, line)


class _Root(_Statement):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._blocks = {}

        self._should_indent = True

    @property
    def should_append(self) -> bool:
        self._raise_invalid_operation(
            "_Root cannot be appended to other statements")

    def append_block_statement(self, block: "_Block"):
        """
        Append a block to the root.

        The block should be appended to both the root and the current indent.
        """
        if block.block_name in self._blocks.keys():
            raise self._raise_invalid_operation(
                "Block with name {} has already been defined"
                .format(block.block_name))

        self._blocks[block.block_name] = block

    def _print_code_impl(self, printer: CodePrinter):
        self._writelines_with_comment(printer, [
            "import futurefinity",
            "class _TplCurrentNamespace(futurefinity.templating.Namespace):"
        ])

        with printer.code_indent():
            self._writeline_with_comment(
                printer,
                "async def _render_body_str(self) -> "
                "futurefinity.compat.Text:")

            with printer.code_indent():
                self._writeline_with_comment(printer, "__tpl_result__ = \"\"")

                for statement in self._statements:
                    statement.print_code(printer)

                self._writeline_with_comment(printer, "return __tpl_result__")

            for block in self._blocks.values():
                block.print_block_code(printer)


class _Include(_Statement):
    _keywords = ("include", )

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(
            printer,
            "__tpl_result__ += await self._include_tpl({})".format(self._rest))


class _Inherit(_Statement):
    _keywords = ("inherit", )

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(
            printer,
            "await self._add_parent({})".format(self._rest))


class _Block(_Statement):
    _keywords = ("block", )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

        self._block_name = self._rest.strip()

        if not self._is_allowed_name(self._block_name):
            raise ParseError(
                "Invalid Block Statement. Block Name expected, got: {} {}."
                .format(self._keyword, self._rest))

    @property
    def block_name(self):
        """
        Return the block name.
        """
        return self._block_name

    @staticmethod
    def _is_allowed_name(name: str) -> bool:
        """
        Check if this is a valid function name.
        """
        return (re.fullmatch(_ALLOWED_BLOCK_NAME, name) is not None)

    def print_block_code(self, printer: CodePrinter):
        try:
            self._writelines_with_comment(printer, [
                "@staticmethod",
                "async def _render_block_{}_str(self) -> str:"
                .format(self._block_name)
            ])
            with printer.code_indent():
                self._writeline_with_comment(
                    printer, "__tpl_result__ = \"\"")

                for statement in self._statements:
                    statement.print_code(printer)

                self._writeline_with_comment(
                    printer, "return __tpl_result__")

        except Exception as e:
            self._raise_code_gen_error(
                "Error occurred during code generation in the block {}"
                .format(self.block_name),
                from_err=e)

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(
            printer,
            "__tpl_result__ += await self.blocks.{}(_defined_here=True)"
            .format(self._block_name))


class _Indent(_Statement):
    _keywords = ("if", "with", "for", "while", "try", "async")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(printer, "{}:".format(self.statement_str))

        with printer.code_indent():
            for statement in self._statements:
                statement.print_code(printer)

            self._writeline_with_comment(printer, "pass")
            # In case there's nothing inside the indent.


class _Unindent(_Statement):
    _keywords = ("end", )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_unindent = True
        self._should_append = False


class _HalfIndent(_Unindent, _Indent):
    _keywords = ("else", "elif", "except", "finally")

    def __init__(self, *args, **kwargs):
        _Statement.__init__(self, *args, **kwargs)

        self._should_indent = True
        self._should_unindent = True


class _Inline(_Statement):
    _keywords = ("break", "continue", "import", "raise", "from")

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(printer, self.statement_str)


class _Output(_Statement):
    _keywords = ("=", "r=", "raw=", "u=", "url=", "j=", "json=", "h=", "html=")

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(
            printer,
            "__tpl_output_raw_result__ = "
            "futurefinity.encoding.ensure_str({}, "
            "self._context.input_encoding)".format(self._rest))

        if self._keyword == "=":
            self._writeline_with_comment(
                printer,
                "__tpl_output_result__ = "
                "self.default_escape(__tpl_output_raw_result__)")

        elif self._keyword in ("r=", "raw="):
            self._writeline_with_comment(
                printer,
                "__tpl_output_result__ = __tpl_output_raw_result__")

        elif self._keyword in ("u=", "url="):
            self._writeline_with_comment(
                printer,
                "__tpl_output_result__ = "
                "futurefinity.encoding.escape_url("
                "__tpl_output_raw_result__, "
                "with_plus=self.escape_url_with_plus)")

        elif self._keyword in ("j=", "json="):
            self._writeline_with_comment(
                printer,
                "__tpl_output_result__ = "
                "futurefinity.encoding.escape_json("
                "__tpl_output_raw_result__)")

        elif self._keyword in ("h=", "html="):
            self._writeline_with_comment(
                printer,
                "__tpl_output_result__ = "
                "futurefinity.encoding.escape_html("
                "__tpl_output_raw_result__)")

        else:
            raise CodeGenerationError(
                "Unknown Type of Output: {}".format(self._keyword))

        self._writeline_with_comment(
            printer, "__tpl_result__ += __tpl_output_result__")


class _Plain(_Statement):
    def __init__(self, plain_str: compat.Text, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._plain_str = plain_str

    def _print_code_impl(self, printer: CodePrinter):
        assert isinstance(self._plain_str, str)
        self._writeline_with_comment(
            printer,
            "__tpl_result__ += {}".format(repr(self._plain_str)))


class _Comment(_Statement):
    _keywords = ("#", )

    def _print_code_impl(self, printer: CodePrinter):
        pass  # Just Print Nothing.


class _Code(_Statement):
    _keywords = ("@", )

    def _print_code_impl(self, printer: CodePrinter):
        self._writeline_with_comment(printer, self._rest)


class _Parser:
    """
    The one-time, non-reusable template parser.
    """
    _statements = (_Include, _Inherit, _Block, _Indent, _Unindent, _HalfIndent,
                   _Inline, _Output, _Plain, _Comment, _Code)

    def __init__(self, tpl: "Template"):
        self._tpl = tpl
        self._mutex_lock = threading.Lock()

        self._content_io = io.StringIO(self._tpl._tpl_content)

        self._current_at = 0
        self._current_line = ""

        self._finished = False

    def _move_to_next_line(self):
        assert not self._finished, "Parsing has already been finished."

        if self._current_line:
            self._raise_parse_error(
                "Parsing of the last line is not completed", self.current_at)

        new_line = self._content_io.readline()

        if not new_line:
            raise _ReadFinished

        self._current_at += 1
        self._current_line = new_line

    @property
    def root(self) -> _Root:
        if not self._finished:
            self._parse()

        return self._root

    def _raise_parse_error(
        self, message: compat.Text, line: Union[int, compat.Text]="<unknown>",
            from_err: Optional[BaseException]=None):
        """
        Raise a `ParseError`.
        """
        err_str = "{} in file {} at line {}.".format(
            message.strip(), self._tpl._path, line)

        if from_err:
            raise ParseError(err_str) from from_err

        else:
            raise ParseError(err_str)

    @property
    def current_at(self) -> int:
        """
        Return the current line number that the parser points to.
        """
        return self._current_at

    def _gen_comment(self) -> compat.Text:
        return "in file {} at line {}".format(
            self._tpl._path, self._current_at)

    def _find_next_begin_mark(self) -> int:
        assert not self._finished, "Parsing has already been finished."

        start_pos = 0

        while True:
            pos = self._current_line.find(_BEGIN_MARK, start_pos)

            if pos == -1:
                return -1

            elif self._current_line[pos + len(_BEGIN_MARK):].startswith(
             _ESCAPE_MARK):
                start_pos = pos + len(_BEGIN_MARK)
                end_pos = start_pos + len(_ESCAPE_MARK)

                self._current_line = (
                    self._current_line[:start_pos] +
                    self._current_line[end_pos:])

                continue

            else:
                return pos

    def _find_next_end_mark(self) -> int:
        assert not self._finished, "Parsing has already been finished."

        start_pos = 0

        while True:
            pos = self._current_line.find(_END_MARK, start_pos)

            if pos == -1:
                return -1

            elif pos == 0:
                return 0

            elif self._current_line[:pos].endswith(_ESCAPE_MARK):
                start_pos = pos - len(_ESCAPE_MARK)
                end_pos = pos

                self._current_line = (
                    self._current_line[:start_pos] +
                    self._current_line[end_pos:])

                start_pos = pos + len(_END_MARK)

                continue

            else:
                return pos

    def _parse_statement(self, statement_str: compat.Text) -> "_Statement":
        splitted = statement_str.strip().split(" ", 1)

        keyword = splitted[0].strip()
        rest = splitted[1] if len(splitted) > 1 else None

        for Statement in self._statements:
            if keyword in Statement._keywords:
                return Statement(keyword, rest, comment=self._gen_comment())

        else:
            raise ParseError("Unknown Statement Keyword: {}.".format(keyword))

    def _find_next_statement(self) -> _Statement:
        assert not self._finished, "Parsing has already been finished."

        statement_str = ""
        begin_mark_line_no = -1

        while True:
            if not self._current_line:
                try:
                    self._move_to_next_line()

                except _ReadFinished as e:
                    if begin_mark_line_no != -1:
                        self._raise_parse_error(
                            "Cannot find statement end mark "
                            "for begin mark", begin_mark_line_no, from_err=e)

                    elif statement_str:
                        return _Plain(
                            statement_str, comment=self._gen_comment())

                    else:
                        raise

            if begin_mark_line_no == -1:
                begin_mark_pos = self._find_next_begin_mark()

                if begin_mark_pos == -1:
                    statement_str += self._current_line
                    self._current_line = ""

                    continue

                elif begin_mark_pos > 0:
                    statement_str += self._current_line[:begin_mark_pos]
                    self._current_line = self._current_line[begin_mark_pos:]

                    return _Plain(statement_str, comment=self._gen_comment())

                elif statement_str:
                    return _Plain(statement_str, comment=self._gen_comment())

                begin_mark_line_no = self.current_at
                self._current_line = self._current_line[2:]

            end_mark_pos = self._find_next_end_mark()

            if end_mark_pos == -1:
                statement_str += self._current_line
                self._current_line = ""

                continue

            statement_str += self._current_line[:end_mark_pos]
            self._current_line = self._current_line[end_mark_pos + 2:]

            try:
                return self._parse_statement(statement_str)

            except Exception as e:
                self._raise_parse_error(
                    "Error Occurred when parsing statement", self.current_at,
                    from_err=e)

    def _append_to_current(self, statement: _Statement):
        assert not self._finished, "Parsing has already been finished."

        if not statement:
            return

        if self._indents:
            self._indents[-1].append_statement(statement)

        else:
            self._root.append_statement(statement)

    def _unindent_current(self):
        assert not self._finished, "Parsing has already been finished."

        if self._indents:
            self._indents.pop().unindent()

        else:
            self._raise_parse_error(
                "Redundant Unindent Statement", self.current_at)

    def _parse(self):
        with self._mutex_lock:  # Avoid Thread Race.
            if self._finished:
                return

            self._root = _Root(comment=self._gen_comment())
            self._indents = []

            while True:
                try:
                    statement = self._find_next_statement()

                except _ReadFinished:
                    break

                try:
                    if statement.should_unindent:
                        self._unindent_current()

                    if statement.should_append:
                        self._append_to_current(statement)

                    if statement.should_indent:
                        self._indents.append(statement)

                    if isinstance(statement, _Block):
                        self._root.append_block_statement(statement)

                except Exception as e:
                    self._raise_parse_error(
                        "Error Occurred when dealing with statement",
                        self.current_at,
                        from_err=e)

            if self._indents:
                raise ParseError(
                    "Unindented Indent Statement {}."
                    .format(self._indents[-1]._comment))

            self._root.unindent()
            self._finished = True

    @staticmethod
    def _parse_tpl(tpl: "Template") -> _Root:
        parser = _Parser(tpl)
        return parser.root


class Template:
    """
    A compiled, resuable template object.
    """
    def __init__(
        self, tpl_content: AnyStr, path: compat.Text="<string>",
        context: Optional[TemplateContext]=None,
            loader: Optional["BaseLoader"]=None):
        self._path = path

        self._context = context or TemplateContext()

        self._loader = loader

        self._tpl_content = encoding.ensure_str(
            tpl_content, encoding=self._context.input_encoding)

    @cached_property
    def _root(self) -> _Root:
        return _Parser._parse_tpl(self)

    @cached_property
    def _compiled_code(self):
        printer = CodePrinter(path=self._path)
        self._root.print_code(printer)
        return printer.compiled_code

    def _get_namespace(
        self, tpl_globals: Optional[
            Mapping[compat.Text, Any]]=None) -> Namespace:
        tpl_globals = tpl_globals or {}

        exec(self._compiled_code, tpl_globals)

        tpl_namespace = tpl_globals["_TplCurrentNamespace"](
            tpl=self, tpl_globals=tpl_globals)

        return tpl_namespace

    async def render_str(self, **kwargs) -> compat.Text:
        tpl_namespace = self._get_namespace(tpl_globals=kwargs)

        await tpl_namespace._render()
        return tpl_namespace._tpl_result

    async def render_bytes(self, **kwargs) -> bytes:
        str_result = await self.render_str(**kwargs)

        return encoding.ensure_bytes(str_result, self._context.output_encoding)


class BaseLoader:
    """
    Base Template Loader.

    All Loaders should be a subclass of this class.
    """
    def __init__(self, context: Optional[TemplateContext]=None):
        self._context = context or TemplateContext()
        self._tpl_cache = {}

        self._mutex_lock = asyncio.Lock()

    async def _load_tpl_content(
            self, tpl_path: compat.Text) -> AnyStr:  # pragma: no cover
        """
        Load the template content asynchronously.
        """
        raise NotImplementedError

    async def _find_abs_path(
        self, tpl_path: compat.Text, origin_path: Optional[compat.Text]=None
            ) -> compat.Text:  # pragma: no cover
        """
        Solve the absolute path of the template from the tpl_path based on the
        origin_path(if applicable).

        If no matched file found, it should raise a ``TemplateNotFoundError``.
        """
        raise NotImplementedError

    async def load_tpl(
        self, tpl_path: compat.Text,
            origin_path: Optional[compat.Text]=None) -> Template:
        """
        Load and parse the template asynchronously.
        """
        async with self._mutex_lock:  # Avoid Coroutine Race.
            if tpl_path in self._tpl_cache.keys():
                return self._tpl_cache[tpl_path]

            abs_tpl_path = await self._find_abs_path(
                tpl_path, origin_path=origin_path)

            tpl_content = await self._load_tpl_content(abs_tpl_path)

            tpl = Template(
                tpl_content, path=tpl_path, context=self._context, loader=self)

            if self._context.cache_tpls:
                self._tpl_cache[tpl_path] = tpl

            return tpl


class AsyncFileSystemLoader(BaseLoader):
    """
    An implementation of `BaseLoader` loads files from the file system
    asynchronously.
    """
    def __init__(self, root_path: compat.Text, *args, **kwargs):
        assert isinstance(root_path, str)

        self._root_path = os.path.abspath(root_path)
        if not self._root_path.endswith("/"):
            self._root_path += "/"

        super().__init__(*args, **kwargs)

        self._executor = concurrent.futures.ThreadPoolExecutor()

    @property
    def _loop(self) -> asyncio.AbstractEventLoop:
        return self._context.loop

    async def _find_abs_path(
        self, tpl_path: compat.Text,
            origin_path: Optional[compat.Text]=None) -> compat.Text:
        if origin_path is not None and (not os.path.isabs(tpl_path)):
            origin_dir = os.path.join(
                self._root_path, os.path.dirname(origin_path))

            if not origin_dir.endswith("/"):
                origin_dir += "/"

            if not origin_dir.startswith(self._root_path):
                raise TemplateNotFoundError(
                    "To prevent potential directory traversal attack, "
                    "this path is not acceptable.")

        else:
            origin_dir = self._root_path

        if os.path.isabs(tpl_path):
            if tpl_path.find(":") != -1:
                _, tpl_path = tpl_path.split(":", 1)

                if tpl_path[0] in ("/", "\\"):
                    tpl_path = tpl_path[1:]

            else:
                _, tpl_path = tpl_path.split("/", 1)

        final_tpl_path = os.path.join(origin_dir, tpl_path)

        if os.path.exists(final_tpl_path):
            return final_tpl_path

        raise TemplateNotFoundError("No such file {}.".format(final_tpl_path))

    async def _load_tpl_content(self, tpl_path: compat.Text) -> bytes:
        async with ioutils.aopen(
            tpl_path, "rb", executor=self._executor, loop=self._loop
                ) as tpl_fp:
            return await tpl_fp.read()
