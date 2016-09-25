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

from futurefinity.templating.namespace import Namespace
from futurefinity.templating import Template, TemplateRenderError

import pytest


class EscapingTestCase(TestCase):
    @property
    def _namespace(self):
        return Namespace(Template("Phantasm."), {})

    def test_no_escape(self):
        assert self._namespace.no_escape("<div></div>") == "<div></div>"

    def test_escape_html(self):
        assert self._namespace.escape_html(
            "<div></div>") == "&lt;div&gt;&lt;/div&gt;"

    def test_escape_json(self):
        assert self._namespace.escape_json(
            "{\"\": \"\"}") == '"{\\"\\": \\"\\"}"'

    def test_escape_url_plus(self):
        assert self._namespace.escape_url_plus(
            "?arg=!@#$% ^&*()+"
        ) == "%3Farg%3D%21%40%23%24%25+%5E%26%2A%28%29%2B"

    def test_escape_url_no_plus(self):
        assert self._namespace.escape_url_no_plus(
            "?arg=!@#$% ^&*()+"
        ) == "%3Farg%3D%21%40%23%24%25%20%5E%26%2A%28%29%2B"

    def test_escape_url(self):
        assert self._namespace.escape_url(
            "?arg=!@#$% ^&*()+"
        ) == "%3Farg%3D%21%40%23%24%25+%5E%26%2A%28%29%2B"

    def test_escape_url_set_with_plus_true(self):
        namespace = self._namespace
        namespace.escape_url_with_plus = True

        assert namespace.escape_url_with_plus is True
        assert namespace.escape_url(
            "?arg=!@#$% ^&*()+"
        ) == "%3Farg%3D%21%40%23%24%25+%5E%26%2A%28%29%2B"

    def test_escape_url_set_with_plus_false(self):
        namespace = self._namespace
        namespace.escape_url_with_plus = False

        assert namespace.escape_url_with_plus is False
        assert namespace.escape_url(
            "?arg=!@#$% ^&*()+"
        ) == "%3Farg%3D%21%40%23%24%25%20%5E%26%2A%28%29%2B"

    def test_set_with_plus_to_other(self):
        with pytest.raises(TemplateRenderError):
            self._namespace.escape_url_with_plus = -1

    def test_default_escape(self):
        assert self._namespace.default_escape(
            "<div></div>") == "&lt;div&gt;&lt;/div&gt;"

    def test_default_escape_set_default_escape_json(self):
        namespace = self._namespace
        namespace.default_escape = "json"

        assert namespace.default_escape(
            "{\"\": \"\"}") == '"{\\"\\": \\"\\"}"'

    def test_default_escape_set_default_escape_custom_escape_fn(self):
        namespace = self._namespace

        def custom_escape_fn(raw_str: str) -> str:
            return raw_str + "www"

        namespace.default_escape = custom_escape_fn

        assert namespace.default_escape("anyway ") == "anyway www"

    def test_default_escape_set_default_escape_to_other(self):
        with pytest.raises(TemplateRenderError):
            self._namespace.default_escape = -1


class RenderMethodsTestCase(TestCase):
    @property
    def _namespace(self):
        return Namespace(Template("Phantasm."), {})

    @run_until_complete
    async def test_render_body_str(self):
        with pytest.raises(NotImplementedError):
            await self._namespace._render_body_str()

    @run_until_complete
    async def test_render(self):
        with pytest.raises(NotImplementedError):
            await self._namespace._render()

    @run_until_complete
    async def test_render_finished(self):
        namespace = self._namespace
        namespace._finished = True

        with pytest.raises(TemplateRenderError):
            await namespace._render()
