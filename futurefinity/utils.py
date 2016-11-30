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

from typing import Any, Optional, Union, List, Callable
from types import ModuleType
from . import compat

import sys
import time
import struct
import asyncio
import inspect
import numbers
import calendar
import datetime
import warnings
import functools
import email.utils
import collections.abc

try:
    from typing import Text
    from typing import Awaitable
    from typing import TYPE_CHECKING

except ImportError:
    from typing import TypeVar, Generic, T_co

    Text = str

    class Awaitable(Generic[T_co], extra=collections.abc.Awaitable):
        __slots__ = ()

    TYPE_CHECKING = False


class Identifier:
    """
    Generic Unique Identifier.
    """
    pass


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
    if compat.PY351:
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


class _ModWithDeprecatedAttrs:
    def __init__(self, mod: ModuleType):
        self.__dict__["__module__"] = mod

    def __getattr__(self, name: Text) -> Any:
        mod_attr = getattr(self.__module__, name)

        if isinstance(mod_attr, _DeprecatedAttr):
            return mod_attr.get_attr()

        return mod_attr

    def __setattr__(self, name: Text, attr: Any):
        return setattr(self.__module__, name, attr)

    def __dir__(self) -> List[Text]:
        return dir(mod)


def deprecated_attr(attr, mod_name, message) -> _DeprecatedAttr:
    """
    Mark an attribute as deprecated in a module.
    """
    mod = sys.modules[mod_name]

    if not isinstance(mod, _ModWithDeprecatedAttrs):
        sys.modules[mod_name] = _ModWithDeprecatedAttrs(mod)

    return _DeprecatedAttr(attr, message)


class _CachedPropertyWrapper:
    def __init__(self, func: Callable[[Any], Any]):
        self.func = func
        functools.update_wrapper(self, func)

    def __get__(self, obj: Any, *args, **kwargs) -> Any:
        if obj is None:
            return self
        val = self.func(obj)
        obj.__dict__[self.func.__name__] = val
        return val


def cached_property(func: Callable[[Any], Any]) -> _CachedPropertyWrapper:
    """
    A Cached Property Decorator.

    References:
    https://en.wikipedia.org/wiki/Lazy_evaluation
    https://github.com/faif/python-patterns/blob/master/lazy_evaluation.py
    """
    return _CachedPropertyWrapper(func)
