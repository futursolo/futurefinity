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

from futurefinity.security import get_random_str

import futurefinity.web

import asyncio

import json
import nose2
import requests
import unittest
import functools
import traceback


class GetTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False,
                                                debug=True)

    def test_get_request(self):
        @self.app.add_handler("/get_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                return self.get_link_arg("content")

        server = self.app.listen(8888)

        async def get_requests_result(self):
            try:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        requests.get,
                        ("http://127.0.0.1:8888/get_test"
                         "?content=Hello, World!")
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

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(self.requests_result.text, "Hello, World!")


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
                        requests.post, "http://127.0.0.1:8888/post_test",
                        data={"content": "Hello, World!"}
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


class HeadTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False,
                                                debug=True)

    def test_head_request(self):
        @self.app.add_handler("/head_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                return "Hello, World!"

        server = self.app.listen(8888)

        async def get_requests_result(self):
            try:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        requests.head, "http://127.0.0.1:8888/head_test"
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

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")


class SecureCookieTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

        self.app_aesgcm = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=get_random_str(32),
            debug=True)

        self.app_hmac = futurefinity.web.Application(
            allow_keep_alive=False,
            security_secret=get_random_str(32),
            aes_security=False,
            debug=True)

        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                cookie_value = self.get_secure_cookie("test_secure_cookie")
                if not cookie_value:
                    cookie_value = get_random_str(100)
                    self.set_secure_cookie("test_secure_cookie", cookie_value)
                    return json.dumps([False, cookie_value])
                return json.dumps([True, cookie_value])

        self.app_aesgcm.add_handler("/test_secure_cookie",
                                    handler=TestHandler)

        self.app_hmac.add_handler("/test_secure_cookie",
                                  handler=TestHandler)

    async def get_requests_result(self, server):
        try:
            self.requests_result = []
            with requests.Session() as s:
                result_getter = functools.partial(
                    s.get, "http://127.0.0.1:8888/test_secure_cookie"
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


class StaticFileHandlerTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False, static_path="examples/static", debug=True)

    def test_static_file_handler_request(self):
        self.requests_result = None
        self.app.add_handler("/static/(?P<file>.*?)",
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
        with open("examples/static/random_string", "rb") as f:
            random_string = f.read()
        self.assertEqual(self.requests_result.content, random_string)


class SessionTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(debug=True)

    def test_keep_alive_request(self):
        @self.app.add_handler("/test_keep_alive")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                return "Hello, World!"

        server = self.app.listen(8888)

        async def get_requests_result(self):
            try:
                self.requests_result = []
                with requests.Session() as s:
                    result_getter = functools.partial(
                        s.get, "http://127.0.0.1:8888/test_keep_alive"
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


class CSRFTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(
            allow_keep_alive=False, csrf_protect=True,
            security_secret=get_random_str(32),
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
                return self._csrf_value

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
                raise futurefinity.web.HTTPError(403)

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


class HeaderTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False,
                                                debug=True)

    def test_custom_header_request(self):
        @self.app.add_handler("/header_test")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                self.set_header("content", self.get_header("content"))
                return "Hello, World!"

        server = self.app.listen(8888)

        async def get_requests_result(self):
            try:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        requests.get, "http://127.0.0.1:8888/header_test",
                        headers={"content": "Hello, World!"}
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

        self.assertEqual(self.requests_result.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(self.requests_result.text, "Hello, World!")


class RedirectTestCollector(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.app = futurefinity.web.Application(allow_keep_alive=False,
                                                debug=True)

    def test_redirect_request(self):
        @self.app.add_handler("/")
        class TestHandler(futurefinity.web.RequestHandler):
            async def get(self, *args, **kwargs):
                return self.redirect("/redirected")

        server = self.app.listen(8888)

        async def get_requests_result(self):
            try:
                self.requests_result = await self.loop.run_in_executor(
                    None, functools.partial(
                        requests.get, "http://127.0.0.1:8888/",
                        allow_redirects=False)
                )
            except:
                traceback.print_exc()
            finally:
                server.close()
                await server.wait_closed()
                self.loop.stop()

        asyncio.ensure_future(get_requests_result(self))
        self.loop.run_forever()

        self.assertEqual(self.requests_result.status_code, 302,
                         "Wrong Status Code")

        self.assertEqual(self.requests_result.headers["location"],
                         "/redirected")
