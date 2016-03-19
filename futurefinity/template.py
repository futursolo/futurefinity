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

from typing import Union

import asyncio

import os
import functools

try:  # Try to load template.
    import jinja2
except ImportError:  # Point jinja2 to None if it is not found.
    jinja2 = None


if jinja2 is not None:
    Template = jinja2.Template
else:
    Template = None


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
            self.render(template_name, template_dict)
        return wrapper
    return decorator


class TemplateLoader:
    """
    The TemplateLoader.

    The Default template loader of FutureFinity.
    """
    def __init__(self, template_path: Union[list, str],
                 cache_template: bool=True):
        if jinja2 is None:
            raise NotImplementedError(
                ("Currently, `futurefinity.template` needs Jinja2 to work. "
                 "Please install it before using template rendering."))
        if isinstance(template_path, str):
            self.template_path = [template_path]
        elif isinstance(template_path, list):
            self.template_path = template_path
        else:
            raise ValueError("Unsupported template_path type.")

        self.cache_template = cache_template

        self._template_cache = {}

    def find_abs_path(self, template_name: str) -> str:
        """
        Find the absolute path of the template from the template_path.

        If no matched file found, it will raise a ``FileNotFoundError``.
        """
        for current_path in self.template_path:
            file_path = os.path.join(os.path.realpath(current_path),
                                     template_name)
            if os.path.exists(file_path):
                return file_path
        raise FileNotFoundError(
            "No such file %s in template_path" % repr(template_name))

    def load_template_file_content(self, file_path):
        """
        Load a file synchronously. This function can be put into a thread
        executor to load the file content concurrently.
        """
        with open(file_path) as tpl:
            return tpl.read()

    def load_template(self, template_name: str) -> "Template":
        """
        Load and parse the template.
        """
        if template_name in self._template_cache:
            return self._template_cache[template_name]

        file_path = self.find_abs_path(template_name)

        template_content = self.load_template_file_content(file_path)
        parsed_tpl = Template(template_content)
        if self.cache_template:
            self._template_cache[template_name] = parsed_tpl

        return parsed_tpl
