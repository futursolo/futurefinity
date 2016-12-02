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

from futurefinity.tests.utils import (
    TestCase, run_until_complete, get_tests_path)

from futurefinity.security import get_random_str
from futurefinity.ioutils import (
    run_on_executor, get_default_executor, AsyncBytesIO, AsyncStringIO,
    AsyncFileSystemOperations, aopen)

import io
import os
import time
import asyncio


class ExecutorTestCase(TestCase):
    @run_until_complete
    async def test_run_on_executor(self):
        @run_on_executor
        def sync_fn1():
            time.sleep(.1)

        @run_on_executor(executor=get_default_executor())
        def sync_fn2():
            time.sleep(.1)

        start_time = time.time()

        tasks = []

        for i in range(0, 5):
            tasks.append(sync_fn1())
            tasks.append(sync_fn2())

        await asyncio.wait(tasks)

        assert time.time() - start_time < .5

    @run_until_complete
    async def test_get_default_executor(self):
        default_executor = get_default_executor()

        assert default_executor is get_default_executor()

        @run_on_executor
        def child_thread():
            return id(get_default_executor())

        assert id(default_executor) != (await child_thread())


class AsyncIOBaseTestCase(TestCase):
    @run_until_complete
    async def test_async_bytes_io(self):
        content = os.urandom(10)
        bytes_io = await AsyncBytesIO(content)

        async with bytes_io as asyncfp:
            new_content = os.urandom(5)
            await asyncfp.seek(0, io.SEEK_END)

            await asyncfp.write(new_content)

            await asyncfp.seek(0)

            assert (await asyncfp.read()) == content + new_content

        assert bytes_io.closed

    @run_until_complete
    async def test_async_string_io(self):
        content = get_random_str(10)
        string_io = await AsyncStringIO(content)

        async with string_io as asyncfp:
            new_content = get_random_str(5)
            await asyncfp.seek(0, io.SEEK_END)

            await asyncfp.write(new_content)

            await asyncfp.seek(0)

            assert (await asyncfp.read()) == content + new_content

        assert string_io.closed


class AsyncFileSystemOperationsTestCase(TestCase):
    @run_until_complete
    async def test_aope_async_with(self):
        async with aopen(get_tests_path("tpls/index.html")) as asyncfp:
            with open(get_tests_path("tpls/index.html")) as f:
                assert f.read() == await asyncfp.read()

    @run_until_complete
    async def test_aope_await(self):
        asyncfp = await aopen(get_tests_path("tpls/index.html"))
        try:
            with open(get_tests_path("tpls/index.html")) as f:
                assert f.read() == await asyncfp.read()

        finally:
            await asyncfp.close()

