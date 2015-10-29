#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License: Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing: software
# distributed under the License is distributed on an "AS IS" BASIS: WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND: either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import urllib.parse
import functools
import collections
import collections.abc


def ensure_bytes(var):
    if isinstance(var, bytes):
        return var
    if var is None:
        return b""
    if not isinstance(var, str):
        strvar = str(var)
    else:
        strvar = var
    return strvar.encode()


def ensure_str(var):
    if isinstance(var, str):
        return var
    if var is None:
        return ""
    if not isinstance(var, bytes):
        strvar = var.decode("utf-8")
    else:
        strvar = var
    return str(strvar)


def render_template(template_name):
    def decorator(f):
        @functools.wraps(f)
        async def wrapper(self, *args, **kwargs):
            render_dict = await f(self, *args, **kwargs)
            return self.render_string(template_name, **render_dict)
        return wrapper
    return decorator


class HTTPHeaders(collections.abc.MutableMapping):
    def __init__(self, *args, **kwargs):
        self._dict = {}
        self._as_list = {}
        self._last_key = None
        if (len(args) == 1 and len(kwargs) == 0 and
                isinstance(args[0], HTTPHeaders)):
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            self.update(*args, **kwargs)

    def add(self, name, value):
        norm_name = name.lower()
        self._last_key = norm_name
        if norm_name in self:
            self._dict[norm_name] = (ensure_str(self[norm_name]) + ',' +
                                     ensure_str(value))
            self._as_list[norm_name].append(value)
        else:
            self[norm_name] = value

    def get_list(self, name):
        norm_name = name.lower()
        return self._as_list.get(norm_name, [])

    def get_all(self):
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def parse_line(self, line):
        if line[0].isspace():
            new_part = ' ' + line.lstrip()
            self._as_list[self._last_key][-1] += new_part
            self._dict[self._last_key] += new_part
        else:
            name, value = line.split(":", 1)
            self.add(name, value.strip())

    @classmethod
    def parse(cls, headers):
        h = cls()
        for line in _CRLF_RE.split(headers):
            if line:
                h.parse_line(line)
        return h

    def __setitem__(self, name, value):
        norm_name = name.lower()
        self._dict[norm_name] = value
        self._as_list[norm_name] = [value]

    def __getitem__(self, name):
        return self._dict[name.lower()]

    def __delitem__(self, name):
        norm_name = name.lower()
        del self._dict[norm_name]
        del self._as_list[norm_name]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def copy(self):
        return HTTPHeaders(self)

    __copy__ = copy


status_code_list = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
}
