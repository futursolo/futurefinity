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
``futurefinity.utils`` contains a series of utilities for common use.
"""

from typing import Any, Optional, Union

import time
import struct
import numbers
import calendar
import datetime
import email.utils
import collections.abc


default_mark = object()


class FutureFinityError(Exception):
    """
    Basic FutureFinity Error Class.

    All Errors from FutureFinity are based on this class.
    """
    pass


def ensure_bytes(var: Any) -> bytes:
    """
    Try to convert passed variable to a bytes object.
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
    return strvar.encode()


def ensure_str(var: Any) -> str:
    """
    Try to convert passed variable to a str object.
    """
    if isinstance(var, str):
        return var
    if var is None:
        return ""
    if isinstance(var, (bytes, bytearray)):
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

    def add(self, name: Any, value: Any):
        """
        Add a value to the MagicDict.
        """
        self._last_key = name
        if name in self:
            self._as_list[name].append(value)
        else:
            self[name] = value

    def get_list(self, name: Any, default: Optional[Any]=None):
        """
        Return all values with the name in a list.
        """
        return self._as_list.get(name, default)

    def get_first(self, name: Any, default: Optional[Any]=None):
        """
        Get the first value with the name.
        """
        return self._as_list.get(name, [default])[0]

    def items(self):
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def keys(self):
        for key in self._as_list.keys():
            yield key

    def values(self):
        for values in self._as_list.values():
            for value in values:
                yield value

    def __setitem__(self, name: Any, value: Any):
        self._dict[name] = value
        self._as_list[name] = [value]

    def __getitem__(self, name: Any):
        return self._dict[name]

    def __delitem__(self, name: Any):
        del self._dict[name]
        del self._as_list[name]

    def __len__(self):
        length = 0
        for value in self._as_list.values():
            length += len(value)
        return length

    def __iter__(self):
        return iter(self._dict)

    def __str__(self):
        content_list = [(key, value) for (key, value) in self.items()]

        return "MagicDict(%s)" % str(content_list)

    def copy(self):
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
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name: str, default: Optional[str]=None):
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def get_first(self, name: str, default: Optional[str]=None):
        lower_name = name.lower()
        return MagicDict.get_first(self, lower_name, default=default)

    def __setitem__(self, name: str, value: str):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name: str):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name: str):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def __str__(self):
        content_list = [(key, value) for (key, value) in self.items()]

        return "TolerantMagicDict(%s)" % str(content_list)

    def copy(self):
        return TolerantMagicDict(self)

    __copy__ = copy
    __repr__ = __str__


def format_timestamp(ts: Union[numbers.Real, tuple, time.struct_time,
                               datetime.datetime, None]=None) -> str:
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
        raise TypeError("unknown timestamp type: %r" % ts)
    return ensure_str(email.utils.formatdate(ts, usegmt=True))
