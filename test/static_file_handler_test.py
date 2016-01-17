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


class StaticFileHandlerTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False, static_path="example/static", debug=True)

    def test_static_file_handler_request(self):
        self.requests_result = None
        self.app.add_handler(
            "/static/{file}",
            handler=futurefinity.web.StaticFileHandler)

        server = self.app.listen(8888)

        async def get_requests_result(self):
            if not self.requests_result:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        requests.get,
                        "http://127.0.0.1:8888/static/random_string"
                    )
                )
            server.close()
            await server.wait_closed()
            self.loop.stop()
        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")

        self.assertEqual(self.requests_result.headers["content-type"],
                         "application/octet-stream")

        random_string = b""
        with open("example/static/random_string", "rb") as f:
            random_string = f.read()
        self.assertEqual(self.requests_result.content, random_string)
