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

from futurefinity.utils import Text
from .utils import TemplateNotFoundError

from . import template

from typing import Union, Optional, List, Callable

import asyncio

import os
import concurrent.futures


class BaseLoader:
    """
    Base Template Loader.

    All Loaders should be a subclass of this class.
    """
    def __init__(
        self, loop: Optional[asyncio.BaseEventLoop]=None,
        cache_template: bool=True,
        default_escape: Union[Text, Callable[[Text], Text]]="html",
        escape_url_with_plus: bool=True):
        self._loop = loop or asyncio.get_event_loop()

        self._default_escape = default_escape
        self._escape_url_with_plus = escape_url_with_plus

        self._cache_template = cache_template

        self._template_cache = {}

    async def load_template(self, template_name: Text) -> template.Template:
        raise NotImplementedError


class TemplateLoader(BaseLoader):
    """
    The async `TemplateLoader`.

    The Default template loader of `FutureFinity`.
    """
    def __init__(
        self,
            template_path: Union[List[Text], Text], *args, **kwargs):
        super().__init__(*args, **kwargs)
        if isinstance(template_path, str):
            self._template_path = [template_path]

        elif isinstance(template_path, list):
            self._template_path = template_path

        else:
            raise ValueError("Unsupported template_path type.")

        self._executor = concurrent.futures.ThreadPoolExecutor(10)

    def _find_abs_path(self, template_name: Text) -> Text:
        """
        Find the absolute path of the template from the template_path.

        If no matched file found, it will raise a ``TemplateNotFoundError``.
        """
        for current_path in self._template_path:
            file_path = os.path.join(os.path.abspath(current_path),
                                     template_name)

            if os.path.exists(file_path):
                return file_path
        raise TemplateNotFoundError(
            "No such file {} in {}.".format(
                template_name, repr(self._template_path)))

    def _load_tpl_str_sync(self, template_name: Text):
        file_path = self._find_abs_path(template_name)

        with open(file_path) as tpl:
            return tpl.read()

    async def _load_tpl_str(self, template_name: Text) -> Text:
        """
        Load the template content asynchronously through a
        `concurrent.futures.ThreadPoolExecutor`.
        """
        return await self._loop.run_in_executor(
            self._executor, self._load_tpl_str_sync, template_name)

    async def load_template(self, template_name: Text) -> template.Template:
        """
        Load and parse the template asynchronously.
        """
        if template_name in self._template_cache:
            return self._template_cache[template_name]

        tpl_str = await self._load_tpl_str(template_name)

        parsed_tpl = template.Template(
            tpl_str, template_name=template_name,
            template_path=self._find_abs_path(template_name),
            default_escape=self._default_escape,
            loader=self,
            escape_url_with_plus=self._escape_url_with_plus)

        if self._cache_template:
            self._template_cache[template_name] = parsed_tpl

        return parsed_tpl
