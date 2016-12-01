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

from . import compat

from typing import Any

import html
import json
import urllib.parse


def ensure_bytes(var: Any, encoding: compat.Text="utf-8") -> bytes:
    """
    Try to convert the passed variable to a bytes object.
    """
    if isinstance(var, bytes):
        return var

    if isinstance(var, bytearray):
        return bytes(var)

    if var is None:
        return b""

    if not isinstance(var, str):
        strvar = str(var)

    else:
        strvar = var

    return strvar.encode(encoding)


def ensure_str(var: Any, encoding: compat.Text="utf-8") -> compat.Text:
    """
    Try to convert the passed variable to a str object.
    """
    if isinstance(var, str):
        return var

    if var is None:
        return ""

    if isinstance(var, (bytes, bytearray)):
        strvar = var.decode(encoding)

    else:
        strvar = var

    return str(strvar)


def escape_html(var: compat.Text) -> compat.Text:
    """
    Escape the string in a html safe way.
    """
    return html.escape(var)


def escape_json(var: compat.Text) -> compat.Text:
    """
    Escape the string into a json safe string.
    """
    return json.dumps(var)


def escape_url(var: compat.Text, *, with_plus: bool=True) -> compat.Text:
    """
    Escape the string in a url safe way.
    """
    if with_plus:
        return urllib.parse.quote_plus(var)

    else:
        return urllib.parse.quote(var)
