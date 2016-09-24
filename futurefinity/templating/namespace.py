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

from .utils import TemplateRenderError

from typing import Dict, Any, Dict, Callable, Union

from . import template
from . import statement

import typing

import html
import json
import urllib.parse

if hasattr(typing, "TYPE_CHECKING") and typing.TYPE_CHECKING:
    from . import loader


class Namespace:
    def __init__(self, tpl: "template.Template", tpl_globals: Dict[str, Any]):
        self._tpl = tpl
        self._tpl_globals = tpl_globals

        self._finished = False
        self._parent = None

        self.__tpl_result__ = ""

        self._escape_types = {
            "html":  self.escape_html,
            "json": self.escape_json,
            "url": self.escape_url,
            "raw": self.no_escape,
        }

        self.escape_url_with_plus = self._tpl._escape_url_with_plus
        self.default_escape = self._tpl._default_escape

    @property
    def _block_dict(self) -> Dict[str, Any]:
        if not hasattr(self, "_prepared_block_dict"):
            self._prepared_block_dict = {}
            self._prepared_block_dict.update(self._tpl._blocks)

        return self._prepared_block_dict

    @property
    def blocks(self) -> Dict[str, Any]:
        class AttrDict(dict):
            def __getattr__(_self, name: str) -> Callable[[], Any]:
                block_fn = self._block_dict[name].get_block_fn(
                    tpl_namespace=self, tpl_globals=self._sub_globals)

                async def wrapper(_defined_here=False):
                    if _defined_here:
                        if self._parent:
                            return ""

                    return await block_fn()

                return wrapper

            def __setattr__(_self, name: str, value: Any):
                raise NotImplementedError

        return AttrDict(self._tpl._blocks)

    @property
    def parent(self) -> "Namespace":
        if self._parent is None:
            raise TemplateRenderError("Parent is not set.")

        return self._parent

    @property
    def _tpl_result(self) -> str:
        if not self._finished:
            raise TemplateRenderError

        return self.__tpl_result__

    @property
    def _loader(self) -> "loader.TemplateLoader":
        return self._tpl._loader

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

        body_block_smt = statement.BlockStatement(name="block", rest="body")
        body_block_smt.append_statement(self.__tpl_result__)
        body_block_smt.unindent()

        body_block = template.TemplateBlock(
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

    @property
    def default_escape(self) -> Callable[[str], str]:
        if not hasattr(self, "_default_escape"):
            return self.escape_html
            # Default Escape Type from the Templating System is escape_html.

        return self._default_escape

    @default_escape.setter
    def default_escape(self, default_type: Union[str, Callable[[str], str]]):
        if default_type in self._escape_types.keys():
            self._default_escape = self._escape_types[default_type]

        elif callable(default_type):
            self._default_escape = default_type

        else:
            raise TemplateRenderError(
                ("Unknown escape type,"
                 "expecting one of {}, got: {}")
                .format(self._escape_types.keys(), default_escape_type))

    @property
    def escape_url_with_plus(self) -> bool:
        if not hasattr(self, "_escape_url_with_plus"):
            return True

        return self._escape_url_with_plus

    @escape_url_with_plus.setter
    def escape_url_with_plus(self, value: bool):
        if not isinstance(value, bool):
            raise TemplateRenderError(
                "escape_url_with_plus property can only take boolean value.")

        self._escape_url_with_plus = value

    def no_escape(self, raw_str: str) -> str:
        return raw_str

    def escape_html(self, raw_str: str) -> str:
        return html.escape(raw_str)

    def escape_json(self, raw_str: str) -> str:
        return json.dumps(raw_str)

    def escape_url_plus(self, raw_str: str) -> str:
        return urllib.parse.quote_plus(raw_str)

    def escape_url_no_plus(self, raw_str: str) -> str:
        return urllib.parse.quote(raw_str)

    def escape_url(self, raw_str: str) -> str:
        if self._escape_url_with_plus:
            return self.escape_url_plus(raw_str)
        else:
            return self.escape_url_no_plus(raw_str)
