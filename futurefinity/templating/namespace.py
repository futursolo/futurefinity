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

from futurefinity.utils import TYPE_CHECKING
from .utils import TemplateRenderError

from typing import Dict, Any, Dict, Callable, Union

from . import template
from . import statement

import html
import json
import functools
import urllib.parse

if TYPE_CHECKING:
    from . import loader


class BlockAttrs:
    _namespace = None  # type: Namespace

    def __getattr__(self, name: str) -> Callable[[], Any]:
        if name not in self._namespace._tpl._root._block_statements.keys():
            raise TemplateRenderError from KeyError("Unknown Block Name.")

        if name in self._namespace._updated_block_fns.keys():
            block_fn = self._namespace._updated_block_fns[name]
        else:
            block_fn = getattr(
                self._namespace, "_render_block_{}_str".format(name))

        async def wrapper(_defined_here=False):
            if _defined_here and self._namespace._parent is not None:
                return ""

            return await functools.partial(block_fn, self=self._namespace)()

        return wrapper

    def __setattr__(self, name: str, value: Any):
        raise NotImplementedError

    __getitem__ = __getattr__
    __setitem__ = __setattr__


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

        self._child_body = None

        self._updated_block_fns = {}

    @property
    def child_body(self) -> str:
        if self._child_body is None:
            raise TemplateRenderError("There's no child body.")

        return self._child_body

    @property
    def blocks(self) -> Dict[str, Any]:
        class CurrentBlockAttrs(BlockAttrs):
            _namespace = self

        return CurrentBlockAttrs()

    @property
    def parent(self) -> "Namespace":
        if self._parent is None:
            raise TemplateRenderError("Parent is not set.")

        return self._parent

    @property
    def _tpl_result(self) -> str:
        if not self._finished:
            raise TemplateRenderError("Renderring has already been finished.")

        return self.__tpl_result__

    @property
    def _loader(self) -> "loader.TemplateLoader":
        return self._tpl._loader

    @property
    def _sub_globals(self) -> Dict[str, Any]:
        sub_globals = {}

        sub_globals.update(self._tpl_globals)

        if "__TplCurrentNamespace__" in sub_globals.keys():
            del sub_globals["__TplCurrentNamespace__"]

        return sub_globals

    async def _include_tpl(self, template_name: str):
        tpl = await self._loader.load_template(template_name)

        tpl_namespace = tpl._get_namespace(tpl_globals=self._sub_globals)

        await tpl_namespace._render()
        self.__tpl_result__ += tpl_namespace._tpl_result

    def _update_blocks(self, **kwargs):
        self._updated_block_fns.update(**kwargs)

    def _update_child_body(self, child_body: str):
        if self._child_body is not None:
            raise TemplateRenderError("There's already a child body.")

        self._child_body = child_body

    async def _inherit_tpl(self):  # Need to be Changed.
        if self._parent is None:
            return

        self._parent._update_child_body(self.__tpl_result__)

        block_fns = {}

        for key in self._tpl._root._block_statements.keys():
            block_fns[key] = getattr(self, "_render_block_{}_str".format(key))

        self._parent._update_blocks(**block_fns)

        await self._parent._render()

        self.__tpl_result__ = self._parent._tpl_result

    async def _add_parent(self, template_name: str):
        if self._parent is not None:
            raise TemplateRenderError(
                "A template can only inherit from one parent template.")

        parent_tpl = await self._loader.load_template(template_name)

        self._parent = parent_tpl._get_namespace(tpl_globals=self._sub_globals)

    async def _render(self):
        if self._finished:
            raise TemplateRenderError("Renderring has already been finished.")

        self.__tpl_result__ = await self._render_body_str()

        await self._inherit_tpl()
        self._finished = True

    async def _render_body_str(self) -> str:
        raise NotImplementedError

    @property
    def default_escape(self) -> Callable[[str], str]:
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
                .format(self._escape_types.keys(), default_type))

    @property
    def escape_url_with_plus(self) -> bool:
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
