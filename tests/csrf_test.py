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

from futurefinity.security import secret_generator

import futurefinity.web

import asyncio

import nose2
import requests
import unittest
import functools
import traceback


class CSRFTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False, csrf_protect=True,
            security_secret=secret_generator(32),
            debug=True)

    async def get_requests_result(self, server):
        try:
            self.requests_result = []
            with requests.Session() as s:
                self.requests_result.append(
                    await self.loop.run_in_executor(None, functools.partial(
                        s.get, "http://127.0.0.1:8888/csrf_test"
                    ))
                )
                self.requests_result.append(
                    await self.loop.run_in_executor(None, functools.partial(
                        s.post, "http://127.0.0.1:8888/csrf_test",
                        data={"_csrf": self.requests_result[0].text}
                    ))
                )
        except:
            traceback.print_exc()
        finally:
            server.close()
            await server.wait_closed()
            self.loop.stop()

    def test_csrf_request(self):
        @self.app.add_handler("/csrf_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                return self.get_csrf_value()

            def check_csrf_value(self, *args, **kwargs):
                futurefinity.web.RequestHandler.check_csrf_value(self, *args,
                                                                 **kwargs)

            async def post(self, *args, **kwargs):
                return "Hello, World!!"

        server = self.app.listen(8888)

        asyncio.ensure_future(self.get_requests_result(server))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 200,
                         "Wrong Status Code for the First Request.")

        self.assertEqual(self.requests_result[1].status_code, 200,
                         "Wrong Status Code for the Second Request.")
