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
import functools
import json


class SecureCookieTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=security_secret_generator(32),
            debug=True)

    def test_secure_cookie_request(self):
        @self.app.add_handler("/test_secure_cookie")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                aesgcm_value = self.get_secure_cookie("use_aesgcm")
                sign_value = self.get_secure_cookie("use_sign")
                if not (aesgcm_value and sign_value):
                    aesgcm_value = security_secret_generator(100)
                    sign_value = security_secret_generator(100)
                    self.set_secure_cookie("use_aesgcm", aesgcm_value)
                    self.set_secure_cookie("use_sign", sign_value)
                    return json.dumps([False, aesgcm_value, sign_value])
                return json.dumps([True, aesgcm_value, sign_value])

        server = self.loop.run_until_complete(
            self.loop.create_server(self.app.make_server(), "127.0.0.1", 8888))

        async def get_requests_result(self):
            try:
                await asyncio.sleep(1)  # Waiting for Server Initialized.
                self.requests_result = []
                with requests.Session() as s:
                    result_getter = functools.partial(
                        lambda: s.get(
                            "http://127.0.0.1:8888/test_secure_cookie"
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
                         "Wrong Cookie Status for First Request.")
        self.assertEqual(second_request[0], True,
                         "Wrong Cookie Code for Second Request.")
        self.assertEqual(first_request[1], second_request[1],
                         "Wrong Cookie Content for AES GCM Cookie.")
        self.assertEqual(first_request[2], second_request[2],
                         "Wrong Cookie COntent for Signed Cookie.")
