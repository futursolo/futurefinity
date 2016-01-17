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
from futurefinity.interface.secure_cookie import AESGCMSecureCookieInterface
from futurefinity.interface.secure_cookie import HMACSecureCookieInterface

import futurefinity.web


import json
import nose2
import asyncio
import requests
import unittest
import functools


class SecureCookieTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app_default = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=security_secret_generator(32),
            debug=True)
        self.app_aesgcm = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=security_secret_generator(32),
            debug=True)
        self.app_aesgcm.interfaces.set("secure_cookie",
                                       AESGCMSecureCookieInterface())
        self.app_hmac = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=security_secret_generator(32),
            debug=True)
        self.app_hmac.interfaces.set("secure_cookie",
                                     HMACSecureCookieInterface())

        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                cookie_value = self.get_secure_cookie("test_secure_cookie")
                if not cookie_value:
                    cookie_value = security_secret_generator(100)
                    self.set_secure_cookie("test_secure_cookie", cookie_value)
                    return json.dumps([False, cookie_value])
                return json.dumps([True, cookie_value])

        self.app_default.add_handler("/test_secure_cookie",
                                     handler=TestHandler)

        self.app_aesgcm.add_handler("/test_secure_cookie",
                                    handler=TestHandler)

        self.app_hmac.add_handler("/test_secure_cookie",
                                  handler=TestHandler)

    async def get_requests_result(self, server):
        try:
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

    def test_default_secure_cookie_request(self):
        self.requests_result = []
        server = self.app_default.listen(8888)

        asyncio.ensure_future(self.get_requests_result(server))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 200,
                         "Wrong Status Code for First Default Request.")

        self.assertEqual(self.requests_result[1].status_code, 200,
                         "Wrong Status Code for Second Default Request.")

        first_request = self.requests_result[0].json()
        second_request = self.requests_result[1].json()

        self.assertEqual(first_request[0], False,
                         "Wrong Cookie Status for First Default Request.")
        self.assertEqual(second_request[0], True,
                         "Wrong Cookie Code for Second Default Request.")
        self.assertEqual(first_request[1], second_request[1],
                         "Wrong Cookie Content for Default Secure Cookie.")

    def test_aesgcm_secure_cookie_request(self):
        self.requests_result = []
        server = self.app_aesgcm.listen(8888)

        asyncio.ensure_future(self.get_requests_result(server))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 200,
                         "Wrong Status Code for First AESGCM Request.")

        self.assertEqual(self.requests_result[1].status_code, 200,
                         "Wrong Status Code for Second AESGCM Request.")

        first_request = self.requests_result[0].json()
        second_request = self.requests_result[1].json()

        self.assertEqual(first_request[0], False,
                         "Wrong Cookie Status for First AESGCM Request.")
        self.assertEqual(second_request[0], True,
                         "Wrong Cookie Code for Second AESGCM Request.")
        self.assertEqual(first_request[1], second_request[1],
                         "Wrong Cookie Content for AESGCM Secure Cookie.")

    def test_hmac_secure_cookie_request(self):
        self.requests_result = []
        server = self.app_hmac.listen(8888)

        asyncio.ensure_future(self.get_requests_result(server))
        self.loop.run_forever()

        self.assertEqual(self.requests_result[0].status_code, 200,
                         "Wrong Status Code for First HMAC Request.")

        self.assertEqual(self.requests_result[1].status_code, 200,
                         "Wrong Status Code for Second HMAC Request.")

        first_request = self.requests_result[0].json()
        second_request = self.requests_result[1].json()

        self.assertEqual(first_request[0], False,
                         "Wrong Cookie Status for First HMAC Request.")
        self.assertEqual(second_request[0], True,
                         "Wrong Cookie Code for Second HMAC Request.")
        self.assertEqual(first_request[1], second_request[1],
                         "Wrong Cookie Content for HMAC Secure Cookie.")
