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

from typing import Any, Optional, Union, List

import sys
import time
import struct
import asyncio
import inspect
import numbers
import calendar
import datetime
import warnings
import email.utils
import collections.abc

try:
    from typing import Text
    from typing import Awaitable
    from typing import TYPE_CHECKING

except:
    from typing import TypeVar, Generic, T_co

    Text = str

    class Awaitable(Generic[T_co], extra=collections.abc.Awaitable):
        __slots__ = ()

    TYPE_CHECKING = False

default_mark = object()

PY350 = sys.version_info[:3] >= (3, 5, 0)
PY351 = sys.version_info[:3] >= (3, 5, 1)
PY352 = sys.version_info[:3] >= (3, 5, 2)


class FutureFinityError(Exception):
    """
    Basic FutureFinity Error Class.

    All Errors from FutureFinity are based on this class.
    """
    pass


def ensure_bytes(var: Any) -> bytes:
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
    return strvar.encode()


def ensure_str(var: Any) -> Text:
    """
    Try to convert the passed variable to a str object.
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

def ensure_future(coro_or_future, *, loop=None):
    """
    Python 3.5.0 Compatibility Layer.

    Behave like `asyncio.ensure_future` on Python 3.5.1 or higher.
    """
    if PY351:
        return asyncio.ensure_future(coro_or_future, loop=loop)

    if isinstance(
        coro_or_future, asyncio.Future) or asyncio.iscoroutine(
            coro_or_future):

        return asyncio.ensure_future(coro_or_future, loop=loop)

    if inspect.isawaitable(coro_or_future):
        return asyncio.ensure_future(
            _wrap_awaitable(coro_or_future), loop=loop)

    else:
        raise TypeError('A Future, a coroutine or an awaitable is required')

def _wrap_awaitable(awaitable):
    """
    Python 3.5.0 Compatibility Layer.

    from `asyncio.tasks` on Python 3.5.2.
    """
    return (yield from awaitable.__await__())


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

    def __str__(self) -> Text:
        content_list = [(key, value) for (key, value) in self.items()]

        return "MagicDict({})".format(str(content_list))

    def copy(self):
        return MagicDict(self)

    __copy__ = copy
    __repr__ = __str__


class TolerantMagicDict(MagicDict):
    """
    An implementation of case-insensitive one-to-many mapping.

    Everything is the same as `MagicDict`,
    but Keys must be str and are case-insensitive.

    **This doesn't mean that the normal `MagicDict` is mean.**
    """

    def add(self, name: Text, value: Text):
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name: Text, default: Optional[Text]=None):
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def get_first(self, name: Text, default: Optional[Text]=None):
        lower_name = name.lower()
        return MagicDict.get_first(self, lower_name, default=default)

    def __setitem__(self, name: Text, value: Text):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name: Text):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name: Text):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def __str__(self):
        content_list = [(key, value) for (key, value) in self.items()]

        return "TolerantMagicDict({})".format(str(content_list))

    def copy(self):
        return TolerantMagicDict(self)

    __copy__ = copy
    __repr__ = __str__


def format_timestamp(ts: Optional[Union[numbers.Real, tuple, time.struct_time,
                                  datetime.datetime]]=None) -> Text:
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
    return ensure_str(email.utils.formatdate(ts, usegmt=True))


class _DeprecatedAttr:
    def __init__(self, attr: Any, message: Text):
        self._attr = attr
        self._message = message

    def get_attr(self) -> Any:
        warnings.warn(self._message, DeprecationWarning)
        return self._attr


def deprecated_attr(attr, mod_name, message):
    """
    Mark an attribute as deprecated in a module.
    """
    mod = sys.modules[mod_name]

    class _ModWithDeprecatedAttrs:
        def __getattr__(self, name: Text) -> Any:
            mod_attr = getattr(mod, name)

            if isinstance(mod_attr, _DeprecatedAttr):
                return mod_attr.get_attr()

            return mod_attr

        def __setattr__(self, name: Text, attr: Any):
            return setattr(mod, name, attr)

        def __dir__(self) -> List[Text]:
            return dir(mod)

    if not isinstance(mod, _ModWithDeprecatedAttrs):
        sys.modules[mod_name] = _ModWithDeprecatedAttrs()

    return _DeprecatedAttr(attr, message)
