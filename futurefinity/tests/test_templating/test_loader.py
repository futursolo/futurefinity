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

from futurefinity.templating.loader import BaseLoader
from futurefinity.templating import TemplateLoader, TemplateNotFoundError

import os
import pytest


class BaseLoaderTestCase(TestCase):
    @run_until_complete
    async def test_load_template(self):
        loader = BaseLoader()

        with pytest.raises(NotImplementedError):
            await loader.load_template("phantasm.html")


class TemplateLoaderTestCase(TestCase):
    def test_init(self):
        signle_loader = TemplateLoader("./tpls")
        assert signle_loader._template_path == ["./tpls"]

        multi_loader = TemplateLoader([".", "./tpls"])
        assert multi_loader._template_path == [".", "./tpls"]

        with pytest.raises(ValueError):
            TemplateLoader(-1)

    @run_until_complete
    async def test_load_template(self):
        loader = TemplateLoader("futurefinity/tests/tpls")

        with pytest.raises(TemplateNotFoundError):
            await loader.load_template("phantasm.html")

        loaded_tpl = await loader.load_template("index.html")

        with open("futurefinity/tests/tpls/index.html") as f:
            tpl_str = f.read()

        assert loaded_tpl._tpl_str == tpl_str  # Test Correctness.

        sec_loaded_tpl = await loader.load_template("index.html")

        assert loaded_tpl is sec_loaded_tpl  # Test Template Cache.

    @run_until_complete
    async def test_load_template_no_cache(self):
        loader = TemplateLoader(
            "futurefinity/tests/tpls", cache_template=False)

        loaded_tpl = await loader.load_template("index.html")
        sec_loaded_tpl = await loader.load_template("index.html")

        # Test Template Cache Disabled.
        assert loaded_tpl is not sec_loaded_tpl
