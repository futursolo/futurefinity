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

from urllib.parse import parse_qsl
import functools


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


def parse_query(queries):
    parsed_queries = {}
    for query in parse_qsl(queries):
        if query[0] not in parsed_queries.keys():
            parsed_queries[query[0]] = []
        parsed_queries[query[0]].append(query[1])
    return parsed_queries


def parse_header(headers):
    parsed_headers = {}
    for (key, value) in headers.items():
        lower_case_header_name = key.lower()
        if lower_case_header_name not in parsed_headers.keys():
            parsed_headers[lower_case_header_name] = []
        parsed_headers[lower_case_header_name].append(value)
    return parsed_headers


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