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

import futurefinity.ioutils
import futurefinity.testutils

import time
import asyncio

helper = futurefinity.testutils.TestHelper(__file__)


class ExecutorTestCase:
    @helper.run_until_complete
    async def test_run_on_executor(self):
        @futurefinity.ioutils.run_on_executor
        def sync_fn1():
            time.sleep(.1)

        @futurefinity.ioutils.run_on_executor(
            executor=futurefinity.ioutils.get_default_executor())
        def sync_fn2():
            time.sleep(.1)

        start_time = time.time()

        tasks = []

        for i in range(0, 5):
            tasks.append(sync_fn1())
            tasks.append(sync_fn2())

        await asyncio.wait(tasks)

        assert time.time() - start_time < .5

    @helper.run_until_complete
    async def test_get_default_executor(self):
        default_executor = futurefinity.ioutils.get_default_executor()

        assert default_executor is futurefinity.ioutils.get_default_executor()

        @futurefinity.ioutils.run_on_executor
        def child_thread():
            return id(futurefinity.ioutils.get_default_executor())

        assert id(default_executor) != (await child_thread())
