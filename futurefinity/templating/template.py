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

from . import parser
from . import printer
from . import namespace
from . import statement

from typing import Dict, List, Any, Optional

import asyncio

import typing

if hasattr(typing, "TYPE_CHECKING") and typing.TYPE_CHECKING:
    from . import loader


class TemplateBlock:
    def __init__(self, block_smt: statement.BlockStatement, tpl: "Template"):
        self._block_smt = block_smt
        self._tpl = tpl

    @property
    def block_name(self) -> str:
        return self._block_smt.block_name

    @property
    def _compiled_code(self):
        if not hasattr(self, "_prepared_compiled_code"):
            code_printer = TemplateCodePrinter(
                template_name="{} Block: {}".format(
                    self._tpl._template_name, self.block_name),
                result_var="__tpl_result__")

            self._block_smt.print_block_code(code_printer)
            self._prepared_compiled_code = code_printer.compiled_code

        return self._prepared_compiled_code

    def get_block_fn(self, tpl_namespace, tpl_globals: Dict[str, Any]):
        exec(self._compiled_code, tpl_globals)

        block_fn = functools.partial(
            tpl_globals["__tpl_render_block__"], self=tpl_namespace)

        return block_fn


class Template:
    def __init__(
        self, tpl_str: str,
        template_name: Optional[str]=None,
        loader: Optional["loader.TemplateLoader"]=None,
        default_escape: str="html",
            escape_url_with_plus: bool=True):
        self._tpl_str = tpl_str

        self._loader = loader
        self._template_name = template_name

        self._default_escape = default_escape
        self._escape_url_with_plus = escape_url_with_plus

    @property
    def _root(self):
        if not hasattr(self, "_prepared_root"):
            self._prepared_root = parser.TemplateParser(self._tpl_str).root

        return self._prepared_root

    @property
    def _compiled_code(self):
        if not hasattr(self, "_prepared_compiled_code"):
            code_printer = printer.CodePrinter(
                template_name=self._template_name)

            self._root.print_code(code_printer)
            self._prepared_compiled_code = code_printer.compiled_code

        return self._prepared_compiled_code

    @property
    def _blocks(self) -> Dict[str, TemplateBlock]:
        if not hasattr(self, "_prepared_blocks"):
            self._prepared_blocks = {}

            for name, item in self._root._blocks:
                self._prepared_blocks[name] = TemplateBlock(
                    block_smt=item, tpl=self)

        return self._prepared_blocks

    @property
    def _tpl_globals(self):
        tpl_globals = {
            "asyncio": asyncio,
            "_TemplateNamespace": namespace.Namespace,
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
