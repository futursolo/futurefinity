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

from futurefinity.templating import TemplateLoader


class TemplateTestCase(TestCase):
    loader = TemplateLoader(
        "futurefinity/tests/tpls",
        cache_template=False)

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
This is body.

    </body>
</html>
""" == result
