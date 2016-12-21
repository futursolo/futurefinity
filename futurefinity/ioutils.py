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
from typing import Optional, Callable, Union, Any

import asyncio
import aiofiles
import functools
import threading
import aiofiles.base
import concurrent.futures
import aiofiles.threadpool

__all__ = ["get_default_executor", "run_on_executor", "aopen", "wrap"]

_THREAD_LOCALS = threading.local()


def get_default_executor():
    if not hasattr(_THREAD_LOCALS, "default_executor"):
        setattr(_THREAD_LOCALS, "default_executor",
                concurrent.futures.ThreadPoolExecutor())

    return _THREAD_LOCALS.default_executor


def run_on_executor(*args, **kwargs):
    def decorator(
        func: Callable[[Any], Any], *,
            executor: Optional[concurrent.futures.Executor]=None,
            loop: Optional[asyncio.AbstractEventLoop]=None) -> Callable[
                [Any], compat.Awaitable[Any]]:
        if asyncio.iscoroutine(func) or asyncio.iscoroutinefunction(func):
            raise TypeError(
                "coroutines cannot be used with run_on_executor().")

        executor = executor or get_default_executor()

        loop = loop or asyncio.get_event_loop()

        async def wrapper(*args, **kwargs) -> Any:
            fur = loop.run_in_executor(
                executor, functools.partial(func, *args, **kwargs))

            return await fur

        return wrapper

    if len(args) == 1 and len(kwargs) == 0:
        return decorator(args[0])

    elif len(args) > 0:
        raise TypeError(
            "run_on_executor can accept 1 positional arugment "
            "with no keyowrd arguments or only keyword arguments.")

    else:
        return functools.partial(decorator, **kwargs)


def aopen(
    *args, executor: Optional[concurrent.futures.ThreadPoolExecutor]=None,
    loop: Optional[asyncio.AbstractEventLoop]=None, **kwargs
        ) -> aiofiles.base.AiofilesContextManager:
    loop = loop or asyncio.get_event_loop()
    executor = executor or get_default_executor()

    return aiofiles.open(*args, executor=executor, loop=loop, **kwargs)


def wrap(
    *args, executor: Optional[concurrent.futures.ThreadPoolExecutor]=None,
    loop: Optional[asyncio.AbstractEventLoop]=None, **kwargs
        ) -> aiofiles.base.AiofilesContextManager:
    loop = loop or asyncio.get_event_loop()
    executor = executor or get_default_executor()

    return aiofiles.threadpool.wrap(
        *args, executor=executor, loop=loop, **kwargs)
