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

from futurefinity.web import (
    Application, RequestHandler, StaticFileHandler, HTTPError)
from futurefinity.security import get_random_str

from typing import Optional

import pytest
import asyncio
import functools
import http.client
import http.cookies
import urllib.error
import urllib.parse
import urllib.request


def get_app(loop: Optional[asyncio.BaseEventLoop]=None,
            allow_keep_alive=False, csrf_protect=False):
    loop = loop or asyncio.get_event_loop()
    return Application(
        allow_keep_alive=allow_keep_alive, debug=True, loop=loop,
        static_path="futurefinity/tests/statics",
        csrf_protect=csrf_protect,
        security_secret=get_random_str(32))


class GetTestCase(TestCase):
    @run_until_complete
    async def test_get_request(self):
        app = get_app(self._loop)

        @app.add_handler("/get_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                return self.get_link_arg("content")

        srv = app.make_server()
        server = await app.listen(8888)

        try:
            result = await self._loop.run_in_executor(
                None, functools.partial(
                    urllib.request.urlopen,
                    "http://127.0.0.1:8888/get_test?content=test"))

        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 200
        assert result.read() == b"test"


class PostTestCase(TestCase):
    @run_until_complete
    async def test_post_request(self):
        app = get_app(self._loop)

        @app.add_handler("/post_test")
        class TestHandler(RequestHandler):
            async def post(self, *args, **kwargs):
                return self.get_body_arg("content")

        srv = app.make_server()
        server = await app.listen(8888)

        try:
            result = await self._loop.run_in_executor(
                None, functools.partial(
                    urllib.request.urlopen,
                    "http://127.0.0.1:8888/post_test", data=b"content=test"))

        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 200
        assert result.read() == b"test"


class HeadTestCase(TestCase):
    @run_until_complete
    async def test_head_request(self):
        app = get_app(self._loop)

        @app.add_handler("/head_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                return "test"

        server = await app.listen(8888)

        try:
            request = urllib.request.Request(
                "http://127.0.0.1:8888/head_test", method="HEAD")

            result = await self._loop.run_in_executor(
                None, functools.partial(urllib.request.urlopen, request))

        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 200
        assert result.getheader("Content-Length") == "4"


class SecureCookieTestCase(TestCase):
    @run_until_complete
    async def test_secure_cookie_request(self):
        app = get_app(self._loop)

        @app.add_handler("/test_secure_cookie")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                cookie_value = self.get_secure_cookie("test_secure_cookie")
                if not cookie_value:
                    cookie_value = get_random_str(100)
                    self.set_secure_cookie("test_secure_cookie", cookie_value)

                return cookie_value

        server = await app.listen(8888)

        try:
            request = urllib.request.Request(
                "http://127.0.0.1:8888/test_secure_cookie",
                method="GET", headers={"cookie": ""})

            first_result = await self._loop.run_in_executor(
                None, functools.partial(urllib.request.urlopen, request))

            set_cookie_header = first_result.getheader("Set-Cookie")

            cookies = http.cookies.SimpleCookie()
            cookies.load(set_cookie_header)

            cookie_val = cookies["test_secure_cookie"].value

            request = urllib.request.Request(
                "http://127.0.0.1:8888/test_secure_cookie",
                method="GET", headers={
                    "cookie": "test_secure_cookie={};".format(cookie_val)})

            second_result = await self._loop.run_in_executor(
                None, functools.partial(urllib.request.urlopen, request))

        finally:
            server.close()
            await server.wait_closed()

        assert first_result.status == 200
        assert second_result.status == 200

        first_body = first_result.read()
        second_body = second_result.read()

        assert first_body == second_body


class StaticFileHandlerTestCase(TestCase):
    @run_until_complete
    async def test_static_file_handler_request(self):
        app = get_app(self._loop)
        app.add_handler("/statics/(?P<file>.*?)", handler=StaticFileHandler)

        server = await app.listen(8888)

        try:
            result = await self._loop.run_in_executor(
                None, functools.partial(
                    urllib.request.urlopen,
                    "http://127.0.0.1:8888/statics/random_str"))

        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 200
        assert result.getheader("Content-Type") == "application/octet-stream"

        with open("futurefinity/tests/statics/random_str", "rb") as f:
            assert f.read() == result.read()


class KeepAliveTestCase(TestCase):
    fur = None  # type: Optional[asyncio.Future]

    @run_until_complete
    async def test_keep_alive_request(self):
        app = get_app(allow_keep_alive=True, loop=self._loop)

        @app.add_handler("/test_keep_alive")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                if fur:
                    fur.set_result(1)
                return str(id(self.connection))

        server = await app.listen(8888)

        try:
            conn = http.client.HTTPConnection("localhost", 8888)

            fur = asyncio.Future()

            conn.request("GET", "/test_keep_alive")

            await fur
            first_result = conn.getresponse()
            first_body = first_result.read()

            fur = asyncio.Future()

            conn.request("GET", "/test_keep_alive")

            await fur
            second_result = conn.getresponse()
            second_body = second_result.read()

        finally:
            server.close()
            await server.wait_closed()

        assert first_result.status == 200
        assert second_result.status == 200

        assert first_body == second_body


class CSRFTestCase(TestCase):
    @run_until_complete
    async def test_csrf_request(self):
        app = get_app(self._loop, csrf_protect=True)

        @app.add_handler("/csrf_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                return self._csrf_value

            def check_csrf_value(self, *args, **kwargs):
                super().check_csrf_value(*args, **kwargs)

            async def post(self, *args, **kwargs):
                return "Hello, World!!"

        server = await app.listen(8888)

        try:
            first_result = await self._loop.run_in_executor(
                None, functools.partial(
                    urllib.request.urlopen,
                    "http://127.0.0.1:8888/csrf_test"))

            csrf_value = first_result.read().decode()

            request = urllib.request.Request(
                "http://127.0.0.1:8888/csrf_test", method="GET",
                headers={"cookie": "_csrf={}".format(csrf_value)},
                data="_csrf={}".format(csrf_value).encode())

            second_result = await self._loop.run_in_executor(
                None, functools.partial(urllib.request.urlopen, request))

        finally:
            server.close()
            await server.wait_closed()

        assert first_result.status == 200
        assert second_result.status == 200


class HTTPErrorTestCase(TestCase):
    @run_until_complete
    async def test_error_request(self):
        app = get_app(loop=self._loop)

        @app.add_handler("/http_error_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                raise HTTPError(403)

        @app.add_handler("/custom_error_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                "" + 233

        server = await app.listen(8888)

        try:
            with pytest.raises(urllib.error.HTTPError) as err_first:
                first_result = await self._loop.run_in_executor(
                    None, functools.partial(
                        urllib.request.urlopen,
                        "http://127.0.0.1:8888/http_error_test"))

            assert err_first.value.code == 403

            with pytest.raises(urllib.error.HTTPError) as err_second:
                second_result = await self._loop.run_in_executor(
                    None, functools.partial(
                        urllib.request.urlopen,
                        "http://127.0.0.1:8888/custom_error_test"))

            assert err_second.value.code == 500

        finally:
            server.close()
            await server.wait_closed()


class HeaderTestCase(TestCase):
    @run_until_complete
    async def test_custom_header_request(self):
        app = get_app(loop=self._loop)

        @app.add_handler("/header_test")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                self.set_header("content", self.get_header("content"))
                return "Hello, World!"

        server = await app.listen(8888)

        try:
            request = urllib.request.Request(
                "http://127.0.0.1:8888/header_test",
                headers={"content": "Hello, World!"})

            result = await self._loop.run_in_executor(
                None, functools.partial(urllib.request.urlopen, request))

        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 200
        assert result.read() == b"Hello, World!"


class RedirectTestCase(TestCase):
    @run_until_complete
    async def test_redirect_request(self):
        fur = None  # type: Optional[asyncio.Future]
        app = get_app(loop=self._loop)

        @app.add_handler("/")
        class TestHandler(RequestHandler):
            async def get(self, *args, **kwargs):
                if fur:
                    fur.set_result(1)
                return self.redirect("/redirected")

        server = await app.listen(8888)

        try:
            conn = http.client.HTTPConnection("localhost", 8888)

            fur = asyncio.Future()

            conn.request("GET", "/")

            await fur
            result = conn.getresponse()
        finally:
            server.close()
            await server.wait_closed()

        assert result.status == 302
        assert result.getheader("location") == "/redirected"
