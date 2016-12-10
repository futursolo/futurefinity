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

from typing import Optional, Callable, Any

from setuptools.command.test import test as BaseTestCommand

from . import compat

import os
import asyncio
import functools


__all__ = ["TestHelper", "TestCommand"]


class TestHelper:
    def __init__(self, file: compat.Text):
        self._root_path = os.path.dirname(os.path.abspath(file))

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_event_loop()
        loop.set_debug(True)

        return loop

    def get_tests_path(
            self, sub_path: Optional[compat.Text]=None) -> compat.Text:
        if sub_path:
            return os.path.abspath(
                os.path.realpath(os.path.join(self._root_path, sub_path)))

        return self._root_path

    def run_until_complete(
            self, f) -> Callable[[Callable[..., compat.Awaitable[Any]]], None]:
        @functools.wraps(f)
        def wrapper(_self, *args, **kwargs):
            return self.loop.run_until_complete(
                asyncio.wait_for(f(_self, *args, **kwargs), timeout=10))
            # In the test, the timeout for one task is 10s.

        return wrapper


class TestCommand(BaseTestCommand):
    user_options = [
        ("test-args=", "a", "Arguments to pass to Test Suite(pytest).")]

    def initialize_options(self):
        super().initialize_options()
        self.test_args = []

    def finalize_options(self):
        if isinstance(self.test_args, str):
            self.test_args = self.test_args.split(" ")

    def run_tests(self):
        args = self.test_args

        try:
            import pytest

        except ImportError as e:
            raise RuntimeError(
                "Cannot Import pytest. Try installing test requirements."
                ) from e

        raise SystemExit(pytest.main(args=args))
