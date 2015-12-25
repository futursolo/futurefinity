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

from futurefinity.utils import *
import unittest
import nose2
import requests
import asyncio
import futurefinity.web
import futurefinity.interface.session
import functools
import json
import aioredis


class SessionTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=security_secret_generator(32),
            debug=True)
        self.pool = self.loop.run_until_complete(aioredis.create_pool(
            ("localhost", 6379),
            minsize=5, maxsize=10))

        self.app.interfaces.set(
            "session",
            futurefinity.interface.session.RedisSessionInterface(
                pool=self.pool))

    def test_session_request(self):
        @self.app.add_handler("/test_session")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                test_value = await self.get_session("test_value", None)
                if not test_value:
                    test_value = security_secret_generator(100)
                    await self.set_session(
                        "test_value",
                        test_value)
                    return json.dumps([False, test_value])
                return json.dumps([True, test_value])

        server = self.loop.run_until_complete(
            self.loop.create_server(self.app.make_server(), "127.0.0.1", 8888))

        async def get_requests_result(self):
            try:
                await asyncio.sleep(1)  # Waiting for Server Initialized.
                self.requests_result = []
                with requests.Session() as s:
                    result_getter = functools.partial(
                        lambda: s.get(
                            "http://127.0.0.1:8888/test_session"
                        )
                    )
                    self.requests_result.append(
                        await self.loop.run_in_executor(None, result_getter)
                    )
                    self.requests_result.append(
                        await self.loop.run_in_executor(None, result_getter)
                    )
            except:
                traceback.print_exc()
            finally:
                server.close()
                await server.wait_closed()
                self.loop.stop()

        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 200,
                         "Wrong Status Code for First Request.")

        self.assertEqual(self.requests_result[1].status_code, 200,
                         "Wrong Status Code for Second Request.")

        first_request = self.requests_result[0].json()
        second_request = self.requests_result[1].json()

        self.assertEqual(first_request[0], False,
                         "Wrong Session Status for First Request.")
        self.assertEqual(second_request[0], True,
                         "Wrong Session Code for Second Request.")
        self.assertEqual(first_request[1], second_request[1],
                         "Wrong Cookie Content for Session.")
