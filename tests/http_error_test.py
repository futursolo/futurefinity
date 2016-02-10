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

from futurefinity.protocol import HTTPError

import futurefinity.web

import asyncio

import nose2
import requests
import unittest
import functools


class HTTPErrorTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False)

    async def get_requests_result(self, server):
        try:
            self.requests_result = []
            with requests.Session() as s:
                self.requests_result.append(
                    await self.loop.run_in_executor(None, functools.partial(
                        s.get, "http://127.0.0.1:8888/http_error_test"
                    ))
                )
                self.requests_result.append(
                    await self.loop.run_in_executor(None, functools.partial(
                        s.get, "http://127.0.0.1:8888/custom_error_test"
                    ))
                )
        except:
            traceback.print_exc()
        finally:
            server.close()
            await server.wait_closed()
            self.loop.stop()

    def test_error_request(self):
        @self.app.add_handler("/http_error_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                raise HTTPError(403)

        @self.app.add_handler("/custom_error_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                "" + 233

        server = self.app.listen(8888)

        self.requests_result = []

        asyncio.ensure_future(self.get_requests_result(server))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 403,
                         "Wrong Status Code for First Default Request.")

        self.assertEqual(self.requests_result[1].status_code, 500,
                         "Wrong Status Code for Second Default Request.")
