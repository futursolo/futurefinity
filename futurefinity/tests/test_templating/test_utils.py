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

from futurefinity.tests.utils import TestCase, run_until_complete

from futurefinity.templating import render_template, is_allowed_name


class RenderTemplateDecoratorTestCase(TestCase):
    @run_until_complete
    async def test_render_template_decorator(self):
        tpl_kwargs = {}

        class RequestHandlerMock:
            _body_written = False

            _tpl_name = None
            _tpl_kwargs = None

            @render_template("index.html")
            async def tester(_self, *args, **kwargs):
                return tpl_kwargs

            async def render(_self, template_name: str, template_dict: dict):
                _self._body_written = True
                _self._tpl_name = template_name
                _self._tpl_kwargs = tpl_kwargs

        handler = RequestHandlerMock()
        await handler.tester()

        assert handler._tpl_name == "index.html"
        assert handler._tpl_kwargs is tpl_kwargs

        handler = RequestHandlerMock()
        handler._body_written = True
        await handler.tester()

        assert handler._tpl_name is None
        assert handler._tpl_kwargs is None


class IsAllowedNameFnTestCase(TestCase):
    def test_is_allowed_name(self):
        assert is_allowed_name("qwerty_fn") is True
        assert is_allowed_name("1st_fn") is False
        assert is_allowed_name("*asdf*") is False
