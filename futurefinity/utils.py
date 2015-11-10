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

import futurefinity
import urllib.parse
import functools
import collections
import collections.abc
import cgi
import io
import random
import string
import http.cookies
import time
import datetime
import email.utils
import calendar
import numbers

MAX_HEADER_LENGTH = 4096

MAX_BODY_LENGTH = 52428800  # 50M

MULTIPART_BOUNDARY_HANDLERS = {}

SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PATCH", "PUT",
                     "OPTIONS", "CONNECT")
BODY_EXPECTED_METHODS = ("POST", "PATCH", "PUT")

_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"


class HTTPError(Exception):
    def __init__(self, status_code=200, message=None, *args, **kwargs):
        self.status_code = status_code
        self.message = message


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
    if isinstance(var, bytes):
        strvar = var.decode("utf-8")
    else:
        strvar = var
    return str(strvar)


def render_template(template_name):
    def decorator(f):
        @functools.wraps(f)
        async def wrapper(self, *args, **kwargs):
            render_dict = await f(self, *args, **kwargs)
            if self._written:
                return
            return self.render_string(template_name, **render_dict)
        return wrapper
    return decorator


def decide_http_v1_mark(data):
    crlf_position = data.find(_CRLF_BYTES_MARK * 2)
    lf_position = data.find(_LF_BYTES_MARK * 2)
    if (crlf_position == -1 and lf_position == -1) and len(
       data) < _MAX_HEADER_LENGTH:
        return None  # Request Not Completed, wait.
    elif crlf_position != -1 and lf_position != -1:
        if lf_position > crlf_position:
            return True
        return False
    elif crlf_position != -1:
        return True
    elif lf_position != -1:
        return False
    else:
        raise HTTPError(413)  # 413 Request Entity Too Large


def split_data(data, use_crlf_mark=True, mark_repeat=1, max_part=0):
    spliter = _CRLF_BYTES_MARK
    if isinstance(data, bytes):
        if not use_crlf_mark:
            spliter = _LF_BYTES_MARK
    elif isinstance(data, str):
        if not use_crlf_mark:
            spliter = _LF_MARK
        else:
            spliter = _CRLF_MARK
    else:
        raise ValueError("%s type is not Splittable." % (type(data)))

    spliter = spliter * mark_repeat

    return data.split(spliter, max_part - 1)


def parse_http_v1_header(data, use_crlf_mark=True):
    if isinstance(data, bytes):
        data = data.decode()
    parsed_headers = HTTPHeaders()
    for header in split_data(data, use_crlf_mark=use_crlf_mark):
        (key, value) = header.split(":", 1)
        parsed_headers.add(key.strip(), value.strip())

    return parsed_headers


def parse_http_v1_initial(data, use_crlf_mark=True):
    initial = {
        "http_version": 10,
        "parsed_path": None,
        "parsed_queries": MagicDict(),
        "parsed_headers": None,
        "parsed_cookies": None
    }
    raw_initial, raw_body = split_data(data, use_crlf_mark=use_crlf_mark,
                                       mark_repeat=2, max_part=2)
    raw_initial = raw_initial.decode()

    basic_info, headers = split_data(raw_initial,
                                     use_crlf_mark=use_crlf_mark,
                                     max_part=2)

    basic_info = basic_info.split(" ")

    if len(basic_info) != 3:
        raise HTTPError(400)  # 400 Bad Request

    method, path, http_version = basic_info

    if http_version.lower() == "http/1.1":
        initial["http_version"] = 11
    elif http_version.lower() == "http/1.0":
        initial["http_version"] = 10
    else:
        raise HTTPError(400)  # 400 Bad Request

    initial["parsed_headers"] = parse_http_v1_header(
        headers, use_crlf_mark=use_crlf_mark)

    initial["parsed_headers"][":path"] = path
    initial["parsed_headers"][":method"] = method
    if "host" in initial["parsed_headers"].keys():
        initial["parsed_headers"][
            ":authority"] = initial["parsed_headers"].pop("host")

    if "cookie" in initial["parsed_headers"]:
        initial["parsed_cookies"] = http.cookies.SimpleCookie(
            initial["parsed_headers"].get("cookie"))
    else:
        initial["parsed_cookies"] = http.cookies.SimpleCookie()

    parsed_url = urllib.parse.urlparse(
        initial["parsed_headers"].get(":path"))

    initial["parsed_path"] = parsed_url.path

    for query in urllib.parse.parse_qsl(parsed_url.query):
        initial["parsed_queries"].add(query[0], query[1])

    if initial["parsed_headers"][":method"] in BODY_EXPECTED_METHODS:
        if int(initial["parsed_headers"].get_first(
         "content-length")) > MAX_BODY_LENGTH:
            raise HTTPError(413)  # 413 Request Entity Too Large

    return initial, raw_body


def find_http_v1_multipart_boundary(content_type):
    for field in content_type.split(";"):
        if field.strip().startswith("boundary"):
            return field.split("=", 1)[1].strip().encode()


def parse_http_v1_body(data, content_length, content_type,
                       boundary=None):
    return cgi.FieldStorage(fp=io.BytesIO(data), environ={
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": content_length
    })


def security_secret_generator(length):
        try:
            random_generator = random.SystemRandom()
        except:
            random_generator = random
        return "".join(random_generator.sample(
            string.ascii_letters + string.digits, length))


def format_timestamp(ts=None):
    if not ts:
        ts = time.time()
    if isinstance(ts, numbers.Real):
        pass
    elif isinstance(ts, (tuple, time.struct_time)):
        ts = calendar.timegm(ts)
    elif isinstance(ts, datetime.datetime):
        ts = calendar.timegm(ts.utctimetuple())
    else:
        raise TypeError("unknown timestamp type: %r" % ts)
    return email.utils.formatdate(ts, usegmt=True)


class MagicDict(collections.abc.MutableMapping):
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
        self._last_key = name
        if name in self:
            self._dict[name] = (ensure_str(self[name]) + ',' +
                                ensure_str(value))
            self._as_list[name].append(value)
        else:
            self[name] = value

    def get_list(self, name, default=None):
        return self._as_list.get(name, default)

    def get_all(self):
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def get_first(self, name):
        return self._as_list.get(name, [None])[0]

    def __setitem__(self, name, value):
        self._dict[name] = value
        self._as_list[name] = [value]

    def __getitem__(self, name):
        return self._dict[name]

    def __delitem__(self, name):
        del self._dict[name]
        del self._as_list[name]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def copy(self):
        return MagicDict(self)

    __copy__ = copy


class HTTPHeaders(MagicDict):

    def add(self, name, value):
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name, default=None):
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def __setitem__(self, name, value):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def copy(self):
        return HTTPHeaders(self)

    __copy__ = copy
