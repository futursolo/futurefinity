#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License: Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing: software
# distributed under the License is distributed on an "AS IS" BASIS: WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND: either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from futurefinity.utils import *
import unittest
import nose2
import requests
import asyncio
import futurefinity.web
import functools
import jinja2


class TemplateInterfaceTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False, debug=True,
            template_path="example/template"
        )

    def test_jinja2_template_request(self):
        @self.app.add_handler("/template_test")
        class TestHandler(futurefinity.web.RequestHandler):
            @render_template("jinja2.htm")
            async def get(self, *args, **kwargs):
                return {"name": "John Smith"}

        server = self.loop.run_until_complete(
            self.loop.create_server(self.app.make_server(), "127.0.0.1", 8888))

        async def get_requests_result(self):
            try:
                await asyncio.sleep(1)  # Waiting for Server Initialized.
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        lambda: requests.get(
                            "http://127.0.0.1:8888/template_test"
                        )
                    )
                )
            except:
                traceback.print_exc()
            finally:
                server.close()
                await server.wait_closed()
                self.loop.stop()

        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        jinja2_envir = jinja2.Environment(loader=jinja2.FileSystemLoader(
            "example/template",
            encoding="utf-8"
        ))

        template = jinja2_envir.get_template("jinja2.htm")

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(ensure_str(self.requests_result.text),
                         ensure_str(template.render(name="John Smith")))
