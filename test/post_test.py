#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2015 Futur Solo
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

import futurefinity.web

import nose2
import asyncio
import requests
import unittest
import functools


class PostTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False,
                                                debug=True)

    def test_post_request(self):
        self.requests_result = None

        @self.app.add_handler("/post_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def post(self, *args, **kwargs):
                return self.get_body_arg("content")

        server = self.app.listen(8888)

        async def get_requests_result(self):
            if not self.requests_result:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        lambda: requests.post(
                            "http://127.0.0.1:8888/post_test",
                            data={"content": "Hello, World!"}
                        )
                    )
                )
            server.close()
            await server.wait_closed()
            self.loop.stop()
        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(self.requests_result.text, "Hello, World!")
