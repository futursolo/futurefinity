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

from futurefinity.utils import PY352
from futurefinity.tests.utils import (
    TestCase, run_until_complete, get_tests_path)

from futurefinity.templating import Template, TemplateLoader

import sys
import time
import random
import asyncio


class _AsyncTimeIterator:
    def __init__(self):
        self._time = time.time()

        self._counter_left = random.choice(range(2, 5))

        self._iterated_time = []

    def __aiter__(self):
        if not PY352:
            fur = asyncio.Future()
            fur.set_result(self)
            return fur

        return self

    async def __anext__(self):
        await asyncio.sleep(random.choice(range(1, 5)) / 10)

        if self._counter_left > 0:
            self._counter_left -= 1

            current_time = time.time()
            self._iterated_time.append(current_time)

            return current_time

        else:
            raise StopAsyncIteration


class TemplateTestCase(TestCase):
    loader = TemplateLoader(get_tests_path("tpls"), cache_template=False)

    @run_until_complete
    async def test_inherit(self):
        tpl = await self.loader.load_template("index.html")

        result = await tpl.render_str()

        assert """\
<!DOCTYPE HTML>
<html>
    <head>
        <title>Index Title</title>
    </head>
    <body>
        \n
This is body. The old title is Old Title.

    </body>
</html>
""" == result

    @run_until_complete
    async def test_output(self):
        tpl = Template(
            "Hello, <%= name %>!")
        assert await tpl.render_str(
            name="FutureFinity") == "Hello, FutureFinity!"

    @run_until_complete
    async def test_if_elif_else(self):
        tpl = Template(
            "<% if cond %>cond_str<% elif sub_cond %>sub_cond_str"
            "<% else %>else_str<% end %>")

        first_result = await tpl.render_str(cond=True, sub_cond=True)
        assert first_result == "cond_str"

        second_result = await tpl.render_str(cond=False, sub_cond=True)
        assert second_result == "sub_cond_str"

        third_result = await tpl.render_str(cond=False, sub_cond=False)
        assert third_result == "else_str"

    @run_until_complete
    async def test_statement_escape(self):
        tpl = Template(
            "<%% is the begin mark, and <%r= \"%%> is the end mark. \" %>"
            "<%r= \"<% and\" %> %> only need to be escaped whenever they "
            "have ambiguity of the templating system.")

        result = await tpl.render_str(cond=True, sub_cond=True)
        assert result == (
            "<% is the begin mark, and %> is the end mark. "
            "<% and %> only need to be escaped whenever they "
            "have ambiguity of the templating system.")

    @run_until_complete
    async def test_statement_modifier(self):
        time_iterator = _AsyncTimeIterator()
        tpl = Template(
            "<% async for i in time_iterator %><%r= str(i) %>, <% end %>")

        result = await tpl.render_str(time_iterator=time_iterator)
        assert result == str(time_iterator._iterated_time)[1:-1] + ", "
