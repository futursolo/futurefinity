#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from urllib.parse import urlparse, parse_qsl
from futurefinity.utils import *

import asyncio

import aiohttp
import aiohttp.server
import routes


class HTTPError(Exception):
    def __init__(self, status_code=200, message=None, *args, **kwargs):
        self.status_code = status_code
        self.message = message


class RequestHandler:
    allow_methods = ("get", "post", "head")
    supported_methods = ("get", "head", "post", "delete", "patch", "put",
                         "options")

    def __init__(self, *args, **kwargs):
        self.app = kwargs.get("app")
        self.writer = kwargs.get("writer")
        self.method = kwargs.get("method").lower()
        self.path = kwargs.get("path")
        self.payload = kwargs.get("payload")
        self.http_version = kwargs.get("http_version")
        self.request_headers = kwargs.get("request_headers")

        self._written = False
        self._finished = False
        self.status_code = 200
        self._response_body = b""

    def set_header(self, name, value):
        pass

    def add_header(self, name, value):
        pass

    def get_header(self, name, default=None):
        pass

    def clear_header(self, name):
        pass

    def clear_all_headers(self):
        pass

    def get_cookie(self, name, default=None):
        pass

    def set_cookie(self, name, value):
        pass

    def get_secure_cookie(self, name, default=None):
        pass

    def set_secure_cookie(self, name, value):
        pass

    def clear_cookie(self, name):
        pass

    def clear_all_cookies(self):
        pass

    def write(self, text, clear_text=False):
        self._written = True
        self._response_body += ensure_bytes(text)
        if clear_text:
            self._response_body = ensure_bytes(text)

    async def finish(self):
        if self._finished:
            return

        self._finished = True
        response = aiohttp.Response(
            self.writer, self.status_code, http_version=self.http_version
        )
        response.add_header('Content-Type', 'text/html')
        response.add_header('Content-Length', str(len(self._response_body)))
        response.send_headers()
        response.write(ensure_bytes(self._response_body))
        await response.write_eof()

    def write_error(self, error_code, message=None):
        pass

    async def head(self, *args, **kwargs):
        get_return_text = await self.get(*args, **kwargs)
        if status_code != 200:
            return
        if self._written is True:
            self.set_header("Content-Length", str(len(self._response_body)))
        else:
            self.set_header("Content-Length", str(len(get_return_text)))
        self.write(b"", clear_text=True)

    async def get(self, *args, **kwargs):
        raise HTTPError(405)

    async def post(self, *args, **kwargs):
        raise HTTPError(405)

    async def delete(self, *args, **kwargs):
        raise HTTPError(405)

    async def patch(self, *args, **kwargs):
        raise HTTPError(405)

    async def put(self, *args, **kwargs):
        raise HTTPError(405)

    async def options(self, *args, **kwargs):
        raise HTTPError(405)

    async def handle(self, *args, **kwargs):
        try:
            if self.method not in self.allow_methods:
                raise HTTPError(405)
            body = await getattr(self, self.method)(*args, **kwargs)
            if not self._written:
                self.write(body)
        except HTTPError as e:
            self.write_error(e.status_code, e.message)
        except Exception as e:
            self.write_error(500)
        await self.finish()


class NotFoundHandler(RequestHandler):
    async def handle(self, *args, **kwargs):
        self.write_error(404)
        await self.finish()


class HTTPServer(aiohttp.server.ServerHttpProtocol):
    def __init__(self, *args, app, **kwargs):
        aiohttp.server.ServerHttpProtocol.__init__(self, *args, **kwargs)
        self.app = app

    async def handle_request(self, message, payload):
        await self.app.process_handler(self.writer, message, payload)


class Application:
    def __init__(self, loop=asyncio.get_event_loop()):
        self.loop = loop
        self.handlers = routes.Mapper()

    def make_server(self):
        return (lambda: HTTPServer(app=self, keep_alive=75))

    def listen(self, port, address="127.0.0.1"):
        f = self.loop.create_server(self.make_server(), address, port)
        srv = self.loop.run_until_complete(f)

    def add_handler(self, route_str, name=None):
        def decorator(cls):
            self.handlers.connect(name, route_str, __handler__=cls)
            return cls
        return decorator

    async def process_handler(self, writer, message, payload):
        matched_obj = self.handlers.match(message.path)
        if not matched_obj:
            matched_obj = {"__handler__": NotFoundHandler}
        handler = matched_obj.pop("__handler__")(
            app=self,
            writer=writer,
            method=message.method,
            path=message.path,
            payload=payload,
            http_version=message.version,
            request_headers=message.headers
        )
        await handler.handle(**matched_obj)
