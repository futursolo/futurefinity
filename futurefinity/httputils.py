#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2017 Futur Solo
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
from . import encoding
from . import magicdict
from . import h1connection

from typing import Optional, Union, Mapping, Sequence, Any

from http.cookies import SimpleCookie as HTTPCookies

import time
import numbers
import calendar
import datetime
import functools
import email.utils
import http.client

__all__ = ["HTTPCookies", "status_code_descriptions", "format_timestamp"]

status_code_descriptions = {
    int(key): value for key, value in http.client.responses.items()}
status_code_descriptions.setdefault(451, "Unavailable For Legal Reasons")


def format_timestamp(ts: Optional[Union[numbers.Real, tuple, time.struct_time,
                                  datetime.datetime]]=None) -> compat.Text:
    """
    Make a HTTP Protocol timestamp.
    """
    if ts is None:
        ts = time.time()

    if isinstance(ts, numbers.Real):
        pass

    elif isinstance(ts, (tuple, time.struct_time)):
        ts = calendar.timegm(ts)

    elif isinstance(ts, datetime.datetime):
        ts = calendar.timegm(ts.utctimetuple())

    else:
        raise TypeError("unknown timestamp type: {}".format(ts))

    return encoding.ensure_str(email.utils.formatdate(ts, usegmt=True))


@functools.singledispatch
def parse_headers(data: Any) -> Mapping[compat.Text, compat.Text]:
    # pragma: no cover
    raise ValueError("Unknown Type of input data.")


# For dict-like object.
@parse_headers.register(Mapping[compat.Text, compat.Text])
def _(
    data: Mapping[compat.Text, compat.Text]
        ) -> Mapping[compat.Text, compat.Text]:
    headers = magicdict.TolerantMagicDict()
    for (key, value) in data.items():
        headers.add(key.strip(), value.strip())
    return headers


# For string-like object.
@parse_headers.register(str)
@parse_headers.register(bytes)
def _(data: Union[compat.Text, bytes]) -> Mapping[compat.Text, compat.Text]:
    headers = magicdict.TolerantMagicDict()

    splitted_data = encoding.ensure_str(data).split("\r\n")

    for header in splitted_data:
        if not header:
            continue
        (key, value) = header.split(":", 1)
        headers.add(key.strip(), value.strip())
    return headers


# For list-like object.
@parse_headers.register(Sequence[compat.Text])
def _(data: Sequence[compat.Text]) -> Mapping[compat.Text, compat.Text]:
    headers = magicdict.TolerantMagicDict()
    for (key, value) in data:
        headers.add(key.strip(), value.strip())
    return headers


def build_headers(headers: Mapping[compat.Text, compat.Text]) -> bytes:
    headers_str = ""
    for (name, value) in headers.items():
        headers_str += "{}: {}".format(
            h1connection.capitalize_h1_header[name], value)
        headers_str += "\r\n"

    return encoding.ensure_bytes(headers_str)


def parse_semicolon_header(
        value: compat.Text) -> Mapping[compat.Text, Optional[compat.Text]]:
    header_dict = magicdict.TolerantMagicDict()
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        splitted = part.split("=", 1)
        part_name = splitted.pop(0).strip()
        part_value = splitted.pop().strip() if splitted else None
        if part_value:
            if part_value.startswith('"') and part_value.endswith('"'):
                part_value = part_value[1:-1]
        header_dict.add(part_name, part_value)

    return header_dict


def build_semicolon_header(
    header_dict: Mapping[compat.Text, Optional[compat.Text]]
        ) -> compat.Text:
    header_list = []
    for name, value in header_dict.items():
        part = name.strip()
        if value is not None:
            part += "=" + value.strip()

        header_list.append(part)

    return "; ".join(header_list)


def build_cookies_for_request(
        cookies: HTTPCookies) -> Mapping[compat.Text, compat.Text]:
    """
    Build all the cookies as a request cookie header.
    """
    headers = magicdict.TolerantMagicDict()
    cookie_string = ""

    for cookie_name, cookie_morsel in cookies.items():
        cookie_string += "{}={}; ".format(cookie_name, cookie_morsel.value)

    if cookie_string:
        headers["cookie"] = cookie_string

    return headers


def build_cookies_for_response(
        cookies: HTTPCookies) -> Mapping[compat.Text, compat.Text]:
    """
    Insert all the cookies as response set cookie headers.
    """
    headers = magicdict.TolerantMagicDict()

    for cookie_morsel in cookies.values():
        headers.add("set-cookie", cookie_morsel.OutputString())

    return headers
