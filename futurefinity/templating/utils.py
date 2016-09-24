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

from futurefinity.utils import FutureFinityError

import re
import functools

_ALLOWED_NAME = re.compile(r"^[a-zA-Z]([a-zA-Z0-9\_]+)?$")


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


class ReadFinished(TemplateError):  # Raised when read finished.
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
