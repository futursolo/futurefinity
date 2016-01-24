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

"""
``futurefinity.utils`` contains a series of utilities that are useful to
dealing with HTTP Protocol.

This class is recommend to be imported without namespace.

.. code-block:: python3

  from futurefinity.utils import *

"""

import futurefinity

import time
import random
import struct
import typing
import string
import numbers
import calendar
import datetime
import functools
import collections
import email.utils
import collections.abc

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


def ensure_bytes(var: typing.Any) -> bytes:
    """
    Try to convert passed variable to a bytes object.
    """
    if isinstance(var, bytes):
        return var
    if var is None:
        return b""
    if not isinstance(var, str):
        strvar = str(var)
    else:
        strvar = var
    return strvar.encode()


def ensure_str(var: typing.Any) -> str:
    """
    Try to convert passed variable to a str object.
    """
    if isinstance(var, str):
        return var
    if var is None:
        return ""
    if isinstance(var, bytes):
        strvar = var.decode("utf-8")
    else:
        strvar = var
    return str(strvar)


class MagicDict(collections.abc.MutableMapping):
    """
    An implementation of one-to-many mapping.
    """
    def __init__(self, *args, **kwargs):
        self._dict = {}
        self._as_list = {}
        self._last_key = None
        if (len(args) == 1 and len(kwargs) == 0 and
                hasattr(args[0], "items")):
            for k, v in args[0].items():
                self.add(k, v)
        else:
            self.update(*args, **kwargs)

    def add(self, name, value):
        """
        Add a value to the MagicDict.
        """
        self._last_key = name
        if name in self:
            self._as_list[name].append(value)
        else:
            self[name] = value

    def get_list(self, name, default=None):
        """
        Return all values with the name in a list.
        """
        return self._as_list.get(name, default)

    def get_all(self):
        """
        Iter all values.
        """
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def get_first(self, name, default=None):
        """
        Get the first value with the name.
        """
        return self._as_list.get(name, [default])[0]

    items = get_all

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

    def __str__(self):
        content_list = []
        for key, value in self.items():
            content_list.append((key, value))

        return "MagicDict(%s)" % str(content_list)

    def copy(self):
        """
        Create another instance of MagicDict but contains the same content.
        """
        return MagicDict(self)

    __copy__ = copy
    __repr__ = __str__


class TolerantMagicDict(MagicDict):
    """
    An implementation of case-insensitive one-to-many mapping.

    Everything is the same as MagicDict,
    but Keys must be str and are case-insensitive.

    **This doesn't mean that the normal MagicDict is mean.**
    """
    def add(self, name: str, value: str):
        """
        Add an element and change the name to lowercase.
        """
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name: str, default: typing.Optional[str]=None):
        """
        Get all elements with the name in a list.
        """
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def get_first(self, name: str, default: typing.Optional[str]=None):
        """
        Get the first element with the name.
        """
        lower_name = name.lower()
        return MagicDict.get_first(self, lower_name, default=default)

    def __setitem__(self, name, value):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def __str__(self):
        content_list = []
        for key, value in self.items():
            content_list.append((key, value))

        return "TolerantMagicDict(%s)" % str(content_list)

    def copy(self):
        """
        Create another instance of TolerantMagicDict,
        but contains the same content.
        """
        return TolerantMagicDict(self)

    __copy__ = copy
    __repr__ = __str__


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
            if self._written:
                return
            return self.render_string(template_name, template_dict)
        return wrapper
    return decorator


def security_secret_generator(length: int) -> str:
    """
    Generate a Security Secret securely with SystemGenerator.
    If SystemGenerator not available, use fake random generator as instead.
    """
    try:
        random_generator = random.SystemRandom()
    except:
        random_generator = random
    random_string = ""
    for i in range(0, length):
        random_string += random_generator.choice(
            string.ascii_letters + string.digits + string.punctuation)
    return random_string


def format_timestamp(ts: typing.Union[int, numbers.Real, tuple,
                                      time.struct_time,
                                      datetime.datetime]=None) -> str:
    """
    Make a timestamp that fits HTTP Response.
    """
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
    return ensure_str(email.utils.formatdate(ts, usegmt=True))
