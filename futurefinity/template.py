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
FutureFinity Template.

Examples:

layout.html::
    <html>
        <head>
            <title><%= await get_page_title()s %></title>
        </head>
        <body>
            <% include "header.htm" %>

            <r= await self.blocks.body() %>
        </body>
    </html>

Examples:

header.html::
    <header>
        <nav><%= await get_page_title() %></nav>
    </header>

main.html::
    <% inherit "layout.html" %>
    <main>
        <% try %>
            <% async for article in db.articles.find() %>
                <div>article.title</div>
                <div>article.content</div>
            <% end %>
        <% except Exception as e %>
            <div>Internal Server Error.</div>
            <%= e %>
        <% end %>
    </main>


"""

from futurefinity.utils import ensure_str, FutureFinityError

from collections import namedtuple
from typing import Union, Optional, List, Dict, Any

import asyncio

import os
import re
import html
import json
import string
import functools
import urllib.parse
import concurrent.futures


_ALLOWED_NAME = re.compile(r"^[a-zA-Z]([a-zA-Z0-9\_]+)?$")

_STATEMENT_MODIFIERS = ("async",)

_SEARCH_FINISHED = object()


class TemplateError(FutureFinityError):
    pass


class ParseError(TemplateError):
    pass


class InvalidStatementOperation(TemplateError):
    pass


class CodeGenerationError(TemplateError):
    pass


class TemplateNotFoundError(TemplateError, FileNotFoundError):
    pass


class TemplateRenderError(TemplateError):
    pass


def render_template(template_name: str):
    """
    Decorator to render template gracefully.

    Only effective when nothing is written.

    Example:

    .. code-block:: python3

      @render_template("index.htm")
      async def get(self, *args, **kwargs):
          return {'content': 'Hello, World!!'}

    """
    def decorator(f):
        @functools.wraps(f)
        async def wrapper(self, *args, **kwargs):
            template_dict = await f(self, *args, **kwargs)
            if self._body_written:
                return

            await self.render(template_name, template_dict)
        return wrapper
    return decorator


class TemplateNamespace:
    def __init__(self, tpl: "Template", tpl_globals: Dict[str, Any]):
        self._tpl = tpl
        self._tpl_globals = tpl_globals

        self._finished = False

        self._parent = None

        self.__tpl_result__ = ""

    @property
    def _block_dict(self) -> Dict[str, Any]:
        if not hasattr(self, "_prepared_block_dict"):
            self._prepared_block_dict = {}
            self._prepared_block_dict.update(self._tpl._blocks)

        return self._prepared_block_dict

    @property
    def blocks(self) -> Any:
        class AttrDict(dict):
            def __getattr__(_self, name):
                block_fn = self._block_dict[name]._get_block_fn(
                    tpl_namespace=self, tpl_globals=self._sub_globals)

                async def wrapper(_defined_here=False):
                    if _defined_here:
                        if self._parent:
                            return ""

                    return await block_fn()

                return wrapper

            def __setattr__(_self, name, value):
                raise NotImplementedError

        return AttrDict(self._tpl._blocks)

    @property
    def parent(self):
        if self._parent is None:
            raise TemplateRenderError("Parent is not set.")

        return self._parent

    @property
    def _tpl_result(self):
        if not self._finished:
            raise TemplateRenderError

        return self.__tpl_result__

    @property
    def _loader(self) -> "TemplateLoader":
        return self._tpl._loader

    @property
    def _escaper(self) -> "TemplateEscaper":
        return self._tpl._escaper

    @property
    def _sub_globals(self) -> Dict[str, Any]:
        sub_globals = {}

        sub_globals.update(self._tpl_globals)

        if "CurrentTplNameSpace" in sub_globals.keys():
            del sub_globals["CurrentTplNameSpace"]

        return sub_globals

    async def _include_tpl(self, template_name: str):
        tpl = await self._loader.load_template(template_name)

        tpl_namespace = tpl._get_namespace(tpl_globals=self._sub_globals)

        await tpl_namespace._render()
        self.__tpl_result__ += tpl_namespace._tpl_result

    def _update_blocks(self, **kwargs):
        self._block_dict.update(**kwargs)

    async def _inherit_tpl(self):
        if self._parent is None:
            return

        body_block_smt = TemplateBlockSmt(name="block", rest="body")
        body_block_smt.append_statement(self.__tpl_result__)
        body_block_smt.unindent()

        body_block = _TemplateBlock(
            tpl=self._tpl, block_smt=body_block_smt)

        self._parent._update_blocks(
            body=body_block, **self._block_dict)

        await self._parent._render()

        self.__tpl_result__ = self._parent._tpl_result

    async def _add_parent(self, template_name: str):
        if self._parent is not None:
            raise TemplateRenderError(
                "A template can only inherit from one parent template.")

        parent_tpl = await self._loader.load_template(template_name)

        self._parent = parent_tpl._get_namespace(tpl_globals=self._sub_globals)

    async def _render(self) -> str:
        raise NotImplementedError


class TemplateStatement:
    names = ()

    def __init__(self,
                 name: Optional[str]=None,
                 rest: Optional[str]=None,
                 modifier: Optional[str]=None):
        self._statements = []
        self._finished = False

        self._name = name or ""
        self._rest = rest.strip() if rest else ""
        self._modifier = modifier or ""

        self._allow_indent = False

    @property
    def allow_indent(self):
        return self._allow_indent

    def append_statement(self, statement: Union["TemplateStatement", str]):
        if not self.allow_indent or self._finished:
            raise InvalidStatementOperation

        self._statements.append(statement)

    def unindent(self):
        if not self.allow_indent or self._finished:
            raise InvalidStatementOperation

        self._finished = True

    def _gen_code_for_str(self, code_gener: "CodeGenerator", str_smt):
        code_gener.append_result(repr(ensure_str(str_smt)))

    def gen_code(self, code_gener: "CodeGenerator"):
        raise NotImplementedError


class TemplateRootSmt(TemplateStatement):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._blocks = {}

        self._allow_indent = True

    def add_block(block: "TemplateBlockSmt"):
        if block.block_name in self._blocks.keys():
            raise ParseError(
                "Block with name {} has already been defined."
                .format(block.block_name))

        self._blocks[block.block_name] = block

    def gen_code(self, code_gener: "CodeGenerator"):
        code_gener.write_line(
            "class CurrentTplNameSpace(TemplateNamespace):")

        with code_gener.code_indent():
            code_gener.write_line("async def _render(self):")

            with code_gener.code_indent():
                for smt in self._statements:
                    if isinstance(smt, str):
                        self._gen_code_for_str(code_gener, smt)
                    else:
                        smt.gen_code(code_gener)

                code_gener.write_line("await self._inherit_tpl()")
                code_gener.write_line("self._finished = True")


class TemplateIncludeSmt(TemplateStatement):
    names = ("include", )

    def gen_code(self, code_gener: "CodeGenerator"):
        code_gener.write_line("await self._include_tpl({})".format(self._rest))


class TemplateInheritSmt(TemplateStatement):
    names = ("inherit", )

    def gen_code(self, code_gener: "CodeGenerator"):
        code_gener.write_line(
            "await self._add_parent({})".format(self._rest))


class TemplateBlockSmt(TemplateStatement):
    names = ("block",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._allow_indent = True

        self._block_name = self._rest.strip()

        if re.fullmatch(_ALLOWED_NAME, self._block_name) is None:
            raise ParseError(
                "Invalid Block Statement. Block Name expected, got: {} {}."
                .format(self._name, self._rest))

    @property
    def block_name(self):
        return self._block_name

    def gen_block_code(self, code_gener: "CodeGenerator"):
        code_gener.write_line("async def __tpl_render_block__(self):")

        with code_gener.code_indent():
            code_gener.write_line("__tpl_result__ = \"\"")
            for smt in self._statements:
                if isinstance(smt, str):
                    self._gen_code_for_str(code_gener, smt)
                else:
                    smt.gen_code(code_gener)
            code_gener.write_line("return __tpl_result__")

    def gen_code(self, code_gener: "CodeGenerator"):
        code_gener.append_result(
            "await self.blocks.{}(_defined_here=True)".format(
                self._block_name))


class TemplateIndentSmt(TemplateStatement):
    names = ("if", "with", "for", "while", "try")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._allow_indent = True

    def gen_code(self, code_gener: "CodeGenerator"):
        smt_line = self._name
        if self._modifier:
            smt_line = self._modifier + " " + smt_line
        if self._rest:
            smt_line += " " + self._rest

        smt_line += ":"

        code_gener.write_line(smt_line)

        with code_gener.code_indent():
            for smt in self._statements:
                if isinstance(smt, str):
                    self._gen_code_for_str(code_gener, smt)
                else:
                    smt.gen_code(code_gener)


class TemplateUnindentSmt(TemplateStatement):
    names = ("end",)


class TemplateHalfIndentSmt(TemplateUnindentSmt, TemplateIndentSmt):
    names = ("else", "elif", "except", "finally")


class TemplateSubControlSmt(TemplateStatement):
    names = ("break", "continue")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._allow_indent = False

    def gen_code(self, code_gener: "CodeGenerator"):
        smt_line = self._name
        if self._modifier:
            smt_line = self._modifier + " " + smt_line
        if self._rest:
            smt_line += " " + self._rest

        code_gener.write_line(smt_line)


class TemplateOutputSmt(TemplateStatement):
    names = ("=", "r=", "raw=", "u=", "url=", "j=", "json=", "h=", "html=")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def gen_code(self, code_gener: "CodeGenerator"):
        code_gener.write_line(
            "__tpl_output_raw_result__ = {}".format(self._rest))

        if self._name == "=":
            code_gener.write_line(
                "__tpl_output_result__ = \
                    self._escaper.escape_default(__tpl_output_raw_result__)")

        elif self._name in ("r=", "raw="):
            code_gener.write_line(
                "__tpl_output_result__ = \
                self._escaper.no_escape(__tpl_output_raw_result__)")

        elif self._name in ("u=", "url="):
            code_gener.write_line(
                "__tpl_output_result__ = \
                    self._escaper.escape_url(__tpl_output_raw_result__)")

        elif self._name in ("j=", "json="):
            code_gener.write_line(
                "__tpl_output_result__ = \
                    self._escaper.escape_json(__tpl_output_raw_result__)")

        elif self._name in ("h=", "html="):
            code_gener.write_line(
                "__tpl_output_result__ = \
                    self._escaper.escape_html(__tpl_output_raw_result__)")

        else:
            raise CodeGenerationError(
                "Unknown Type of Output: {}".format(self._name))

        code_gener.append_result("__tpl_output_result__")


_smt_classes = (
    TemplateOutputSmt, TemplateIndentSmt, TemplateHalfIndentSmt,
    TemplateIncludeSmt, TemplateBlockSmt, TemplateUnindentSmt,
    TemplateSubControlSmt, TemplateInheritSmt)


def _get_statement(*args, **kwargs):
    name = args[0] if args else kwargs["name"]

    for SmtClass in _smt_classes:
        if name in SmtClass.names:
            return SmtClass(*args, **kwargs)

    else:
        raise ParseError("Unknown Statement Name: {}.".format(name))


class TemplateParser:
    def __init__(self, begin_mark="<%", end_mark="%>"):

        self._begin_mark = begin_mark
        self._end_mark = end_mark

    def _parse_statement(self, smt_str) -> TemplateStatement:
        splitted_smt_str = smt_str.strip().split(" ", 1)

        if splitted_smt_str[0] in _STATEMENT_MODIFIERS:
            modifier = splitted_smt_str.pop(0)
            splitted_smt_str = splitted_smt_str.strip().split(" ", 1)
        else:
            modifier = None

        name = splitted_smt_str[0]

        if len(splitted_smt_str) > 1:
            rest = splitted_smt_str[1]
        else:
            rest = None

        return _get_statement(name, rest, modifier)

    def _find_next_statement(
        self, tpl_str) -> (
            List[Union[TemplateStatement, str]], Union[object, str]):

        split_result = tpl_str.split(self._begin_mark, 1)
        if len(split_result) == 1:
            return (split_result, _SEARCH_FINISHED)

        smt_list = [split_result[0]]

        split_result = split_result[1].split(self._end_mark, 1)

        if len(split_result) == 1:
            raise ParseError("Cannot Find Statement End Mark.")

        smt_str, rest_str = split_result  # Expand Result

        smt_list.append(self._parse_statement(smt_str))

        return (smt_list, rest_str)

    def parse_str(self, tpl_str: str) -> TemplateRootSmt:
        root = TemplateRootSmt()
        indents = []

        rest_str = tpl_str

        def append_to_current_indent(smt):
            if not smt:
                return

            if indents:
                indents[-1].append_statement(smt)
            else:
                root.append_statement(smt)

        def unindent_current_indent():
            if indents:
                indents.pop().unindent()
            else:
                raise ParseError("Redundant Unindent Statement(s).")

        while True:
            smt_list, rest_str = self._find_next_statement(rest_str)

            for smt in smt_list:
                if isinstance(smt, TemplateUnindentSmt):
                    unindent_current_indent()
                    if not smt.allow_indent:
                        continue

                append_to_current_indent(smt)

                if isinstance(smt, TemplateStatement) and smt.allow_indent:
                    indents.append(smt)

            if rest_str == _SEARCH_FINISHED:
                break

        if indents:
            raise ParseError("Unindented Indent Statement(s).")

        root.unindent()
        return root


class _WithCodeIndent:
    def __init__(self, code_gener: "CodeGenerator"):
        self._code_gener = code_gener

    def __enter__(self):
        self._code_gener._inc_indent_num()

    def __exit__(self, *exc):
        self._code_gener._dec_indent_num()


class CodeGenerator:
    def __init__(
        self, top_indent: int=0,
        template_name: Optional[str]=None,
            indent_mark="    ", end_of_line="\n",
            result_var="self.__tpl_result__"):

        self._indent_num = top_indent
        self._template_name = template_name
        self._indent_mark = indent_mark
        self._end_of_line = end_of_line
        self._result_var = result_var

        self._with_code_indent = _WithCodeIndent(self)

        self._committed_code = ""

        self._finished = False

    def code_indent(self) -> _WithCodeIndent:
        if self._finished:
            raise CodeGenerationError

        return self._with_code_indent

    def _inc_indent_num(self):
        if self._finished:
            raise CodeGenerationError

        self._indent_num += 1

    def _dec_indent_num(self):
        if self._finished:
            raise CodeGenerationError

        self._indent_num -= 1

    def write_line(self, line: str):
        if self._finished:
            raise CodeGenerationError

        self._committed_code += self._indent_mark * self._indent_num

        self._committed_code += line

        self._committed_code += self._end_of_line

    def append_result(self, line: str):
        self.write_line(self._result_var + " += " + line)

    @property
    def finished(self):
        return self._finished

    @property
    def plain_code(self):
        self._finished = True
        return self._committed_code

    @property
    def compiled_code(self):
        if not hasattr(self, "_compiled_code"):
            self._compiled_code = compile(
                self.plain_code,
                "<Template: {}>".format(self._template_name), "exec",
                dont_inherit=True)

        return self._compiled_code


class TemplateEscaper:
    def __init__(
        self, default_escape_type: str="html",
            url_plus_encoding: bool=True):
        self._url_plus_encoding = url_plus_encoding

        if default_escape_type == "html":
            self.escape_default = self.escape_html

        elif default_escape_type == "json":
            self.escape_default = self.escape_json

        elif default_escape_type == "url":
            self.escape_default = self.escape_url

        elif default_escape_type == "raw":
            self.escape_default = self.no_escape

        else:
            raise TemplateRenderError(
                ("Unknown default_escape_type,"
                 "expecting one of html, json, url and raw, got: {}")
                .format(default_escape_type))

    def no_escape(self, raw_str):
        return raw_str

    def escape_html(self, raw_str):
        return html.escape(raw_str)

    def escape_json(self, raw_str):
        return json.dumps(raw_str)

    def escape_url(self, raw_str):
        if self._url_plus_encoding:
            return urllib.parse.quote_plus(raw_str)
        else:
            return urllib.parse.quote(raw_str)


class _TemplateBlock:
    def __init__(self, block_smt: TemplateBlockSmt, tpl: "Template"):
        self._block_smt = block_smt
        self._tpl = tpl

    @property
    def block_name(self) -> str:
        return self._block_smt.block_name

    @property
    def _compiled_code(self):
        if not hasattr(self, "_prepared_compiled_code"):
            code_gener = CodeGenerator(
                template_name="{} Block: {}".format(
                    self._tpl._template_name, self.block_name),
                result_var="__tpl_result__")

            self._block_smt.gen_block_code(code_gener)
            self._prepared_compiled_code = code_gener.compiled_code

        return self._prepared_compiled_code

    def _get_block_fn(self, tpl_namespace, tpl_globals: Dict[str, Any]):
        exec(self._compiled_code, tpl_globals)

        block_fn = functools.partial(
            tpl_globals["__tpl_render_block__"], self=tpl_namespace)

        return block_fn


class Template:
    def __init__(
        self, tpl_str: str,
        template_name: Optional[str]=None,
        loader: Optional["TemplateLoader"]=None,
        parser_kwargs: Dict[str, Any]={},
            escaper_kwargs: Dict[str, Any]={}):
        self._tpl_str = tpl_str

        self._parser_kwargs = parser_kwargs
        self._escaper_kwargs = escaper_kwargs

        self._loader = loader
        self._template_name = template_name

        if self._loader:
            self._parser = self._loader.tpl_parser
            self._escaper = self._loader.tpl_escaper

        else:
            self._parser = TemplateParser(**self._parser_kwargs)
            self._escaper = TemplateEscaper(**self._escaper_kwargs)

    @property
    def _root(self):
        if not hasattr(self, "_prepared_root"):
            self._prepared_root = self._parser.parse_str(self._tpl_str)

        return self._prepared_root

    @property
    def _compiled_code(self):
        if not hasattr(self, "_prepared_compiled_code"):
            code_gener = CodeGenerator(template_name=self._template_name)

            self._root.gen_code(code_gener)
            self._prepared_compiled_code = code_gener.compiled_code

        return self._prepared_compiled_code

    @property
    def _blocks(self) -> Dict[str, _TemplateBlock]:
        if not hasattr(self, "_prepared_blocks"):
            self._prepared_blocks = {}
            for name, item in self._root._blocks:
                self._prepared_blocks[name] = _TemplateBlock(
                    block_smt=item, tpl=self)
        return self._prepared_blocks

    @property
    def _tpl_globals(self):
        tpl_globals = {
            "asyncio": asyncio,
            "TemplateNamespace": TemplateNamespace,
        }

        return tpl_globals

    def _get_namespace(
        self, tpl_globals: Optional[Dict[str, Any]]=None,
            namespace_args: List[Any]=(), namespace_kwargs: Dict[str, Any]={}):
        tpl_globals = tpl_globals or self._tpl_globals
        exec(self._compiled_code, tpl_globals)

        tpl_namespace = tpl_globals["CurrentTplNameSpace"](
            tpl=self, tpl_globals=tpl_globals,
            *namespace_args, **namespace_kwargs)

        return tpl_namespace

    async def render_str(self, **kwargs) -> str:
        tpl_globals = kwargs
        tpl_globals.update(self._tpl_globals)

        tpl_namespace = self._get_namespace(tpl_globals=tpl_globals)

        await tpl_namespace._render()
        return tpl_namespace._tpl_result


class TemplateLoader:
    """
    The TemplateLoader.

    The Default template loader of FutureFinity.
    """
    def __init__(
        self, template_path: Union[list, str],
        loop: Optional[asyncio.BaseEventLoop]=None,
        cache_template: bool=True,
        tpl_kwargs: Dict[str, Any]={},
        escaper_kwargs: Dict[str, Any]={},
        parser_kwargs: Dict[str, Any]={},
            executor: Optional[concurrent.futures.Executor]=None):

        self._loop = loop or asyncio.get_event_loop()

        self._template_path = template_path

        self._tpl_kwargs = tpl_kwargs
        self._escaper_kwargs = escaper_kwargs
        self._parser_kwargs = parser_kwargs

        self._executor = executor or concurrent.futures.ThreadPoolExecutor(
            100)

        self._cache_template = cache_template

        self._tpl_kwargs["loader"] = self

        if isinstance(self._template_path, str):
            self._template_path = [self._template_path]

        elif isinstance(template_path, list):
            pass

        else:
            raise ValueError("Unsupported template_path type.")

        self._template_cache = {}

    @property
    def tpl_parser(self):
        if not hasattr(self, "_parser"):
            self._parser = TemplateParser(**self._parser_kwargs)

        return self._parser

    @property
    def tpl_escaper(self):
        if not hasattr(self, "_escaper"):
            self._escaper = TemplateEscaper(**self._escaper_kwargs)

        return self._escaper

    def _find_abs_path(self, template_name: str) -> str:
        """
        Find the absolute path of the template from the template_path.

        If no matched file found, it will raise a ``FileNotFoundError``.
        """
        for current_path in self._template_path:
            file_path = os.path.join(os.path.realpath(current_path),
                                     template_name)
            if os.path.exists(file_path):
                return file_path
        raise TemplateNotFoundError(
            "No such file %s in template_path" % repr(template_name))

    def _load_tpl_str_sync(self, template_name: str):
        file_path = self._find_abs_path(template_name)

        with open(file_path) as tpl:
            return tpl.read()

    async def _load_tpl_str(self, template_name: str) -> str:
        """
        Load the template content asynchronously through a
        `concurrent.futures.ThreadPoolExecutor`.
        """
        return await self._loop.run_in_executor(
            self._executor, self._load_tpl_str_sync, template_name)

    async def load_template(self, template_name: str) -> Template:
        """
        Load and parse the template.
        """
        if template_name in self._template_cache:
            return self._template_cache[template_name]

        tpl_str = await self._load_tpl_str(template_name)

        parsed_tpl = Template(
            tpl_str, template_name=template_name,
            **self._tpl_kwargs)
        if self._cache_template:
            self._template_cache[template_name] = parsed_tpl

        return parsed_tpl
