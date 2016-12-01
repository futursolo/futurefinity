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

from . import compat
from typing import Any, Optional, Union, List, Callable
from types import ModuleType

import sys
import warnings
import functools


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


class _DeprecatedAttr:
    def __init__(self, attr: Any, message: compat.Text):
        self._attr = attr
        self._message = message

    def get_attr(self) -> Any:
        warnings.warn(self._message, DeprecationWarning)
        return self._attr


class _ModWithDeprecatedAttrs:
    def __init__(self, mod: ModuleType):
        self.__dict__["__module__"] = mod

    def __getattr__(self, name: compat.Text) -> Any:
        mod_attr = getattr(self.__module__, name)

        if isinstance(mod_attr, _DeprecatedAttr):
            return mod_attr.get_attr()

        return mod_attr

    def __setattr__(self, name: compat.Text, attr: Any):
        return setattr(self.__module__, name, attr)

    def __dir__(self) -> List[compat.Text]:
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
