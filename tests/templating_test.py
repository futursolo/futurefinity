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

from futurefinity.templating import render_template, Template, TemplateLoader

import asyncio

import os
import unittest


class TemplateTestCollector(unittest.TestCase):
    def test_render_template_decorator(self):
        result_placer = []

        class RequestHandlerMock:
            _body_written = False

            @render_template("test.htm")
            async def tester(self, *args, **kwargs):
                return {"a": "b"}

            async def render(self, template_name: str, template_dict: dict):
                self._body_written = True
                result_placer.append((template_name, template_dict))

        loop = asyncio.get_event_loop()  # type: asyncio.BaseEventLoop
        handler = RequestHandlerMock()

        loop.run_until_complete(handler.tester())
        loop.run_until_complete(handler.tester())

        self.assertEqual(len(result_placer), 1)
        self.assertEqual(result_placer[0][0], "test.htm")
        self.assertEqual(result_placer[0][1], {"a": "b"})

    def test_template_loader_init_with_signle_path(self):
        loader_single = TemplateLoader(template_path="/tmp")
        loader_multi = TemplateLoader(template_path=["/tmp", "."])
        self.assertRaises(ValueError, TemplateLoader, {})

        self.assertListEqual(loader_single._template_path, ["/tmp"])
        self.assertListEqual(loader_multi._template_path, ["/tmp", "."])

    def test_template_loader_find_abs_path(self):
        loader = TemplateLoader(template_path="examples/template/")
        self.assertEqual(loader._find_abs_path("login.htm"),
                         os.path.realpath("examples/template/login.htm"))
        self.assertRaises(FileNotFoundError, loader._find_abs_path,
                          "login.html")

    def test_template_loader_load_template_file_content(self):
        loop = asyncio.get_event_loop()

        loader = TemplateLoader(template_path="examples/template/")
        file_path = loader._find_abs_path("login.htm")
        with open("examples/template/login.htm") as f:
            self.assertEqual(f.read(), loop.run_until_complete(
                loader._load_tpl_str(file_path)))

    def test_template_loader_load_template(self):
        loop = asyncio.get_event_loop()

        loader = TemplateLoader(template_path="examples/template/")
        loader_loaded_template = loop.run_until_complete(
            loader.load_template("login.htm"))
        with open("examples/template/login.htm") as f:
            test_loaded_template = Template(f.read())

        self.assertEqual(
            loop.run_until_complete(loader_loaded_template.render_str()),
            loop.run_until_complete((test_loaded_template.render_str())))

    def test_template_loader_load_template_cache(self):
        loop = asyncio.get_event_loop()

        loader = TemplateLoader(template_path="examples/template/")
        first_loaded_template = loop.run_until_complete(
            loader.load_template("login.htm"))
        second_loaded_template = loop.run_until_complete(
            loader.load_template("login.htm"))
        self.assertIs(first_loaded_template, second_loaded_template)
