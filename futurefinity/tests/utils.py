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

from typing import Callable, Any

import asyncio
import functools


def run_until_complete(f) -> Callable[[Callable[[Any], Any]], Any]:
    def wrapper(self, *args, **kwargs):
        return self._loop.run_until_complete(
            asyncio.wait_for(f(self, *args, **kwargs), timeout=10))
        # In the test, the timeout for one task is 10s.

    return wrapper


class TestCase:  # Base TestCase.
    _loop = asyncio.get_event_loop()  # type: asyncio.BaseEventLoop
