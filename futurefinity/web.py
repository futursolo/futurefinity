#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License: Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing: software
# distributed under the License is distributed on an "AS IS" BASIS: WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND: either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from futurefinity.utils import *
import futurefinity.server

import asyncio

import routes
import jinja2
import traceback
import http.cookies
import http.client


__all__ = ["ensure_bytes", "ensure_str", "render_template", "WebError"]


class RequestHandler:
    allow_methods = ("GET", "POST", "HEAD")

    def __init__(self, *args, **kwargs):
        self.app = kwargs.get("app")
        self.make_response = kwargs.get("make_response")
        self.method = kwargs.get("method")
        self.path = kwargs.get("path")
        self.matched_path = kwargs.get("matched_path")
        self._request_queries = kwargs.get("queries")
        self.http_version = kwargs.get("http_version")
        self._request_headers = kwargs.get("request_headers")
        self._request_cookies = kwargs.get("request_cookies")
        self._request_body_data = b""
        self._request_body_query = None

        self._response_headers = HTTPHeaders()
        self._response_cookies = http.cookies.SimpleCookie()

        self._body_parsed = False
        self._request_handled = False
        self._written = False
        self._finished = False
        self.status_code = 200
        self._response_body = b""

    def get_query(self, name, default=None):
        return self._request_queries.get(name, [default])[0]

    def get_body_query(self, name, default=None):
        return self._request_body_query.getfirst(name, default)

    def set_header(self, name, value):
        self._response_headers[name] = value

    def add_header(self, name, value):
        self._response_headers.add(name, value)

    def get_header(self, name, default=None):
        return self._request_headers.get_list(name, [default])[0]

    def get_all_headers(self, name, default=None):
        return self._request_headers.get(name, default)

    def clear_header(self, name):
        self._response_headers.remove(name)

    def clear_all_headers(self):
        self._response_headers.clear()

    def get_cookie(self, name, default=None):
        cookie = self._request_cookies.get(name, default)
        if not cookie:
            return default
        return cookie.value

    def set_cookie(self, name, value, domain=None, expires=None, path="/",
                   expires_days=None, secure=False, httponly=False):
        self._response_cookies[name] = value
        if domain:
            self._response_cookies[name]["domain"] = domain
        if expires:
            self._response_cookies[name]["expires"] = expires
        self._response_cookies[name]["path"] = path
        self._response_cookies[name]["max-age"] = expires_days
        self._response_cookies[name]["secure"] = secure
        self._response_cookies[name]["httponly"] = httponly

    def get_secure_cookie(self, name, default=None):
        pass

    def set_secure_cookie(self, name, value):
        pass

    def clear_cookie(self, name):
        if name in self._response_cookies:
            del self._response_cookies[name]

    def clear_all_cookies(self):
        self._response_cookies = http.cookies.SimpleCookie()

    def write(self, text, clear_text=False):
        if self._finished:
            return
        self._written = True
        self._response_body += ensure_bytes(text)
        if clear_text:
            self._response_body = ensure_bytes(text)

    def render_string(self, template_name, **kwargs):
        template = self.app.template_env.get_template(template_name)
        return template.render(**kwargs)

    def render(self, template_name, **kwargs):
        self.write(self.render_string(template_name, **kwargs))

    async def finish(self):
        if self._finished:
            return
        self._finished = True

        if (self._response_body[-2:] != b"\r\n" or
           self._response_body[-1:] != b"\n"):
            self._response_body += b"\r\n"

        if "content-type" not in self._response_headers:
            self.set_header("content-type", "text/html; charset=utf-8;")

        if "content-length" not in self._response_headers:
            self.set_header("content-length",
                            str(len(self._response_body)))

        if "connection" not in self._response_headers:
            self.set_header("connection", "Keep-Alive")

        if "server" not in self._response_headers:
            self.set_header("server", "FutureFinity/0.0.1")

        for cookie_morsel in self._response_cookies.values():
            self._response_headers.add("set-cookie",
                                       cookie_morsel.OutputString())

        self.make_response(status_code=self.status_code,
                           response_headers=self._response_headers,
                           response_body=self._response_body)

    def write_error(self, error_code, message=None):
        self.status_code = error_code
        self.write("<!DOCTYPE HTML>"
                   "<html>"
                   "<head>"
                   "    <title>%(error_code)d: %(status_code_detail)s</title>"
                   "</head>"
                   "<body>"
                   "    <div>%(error_code)d: %(status_code_detail)s</div>" % {
                        "error_code": error_code,
                        "status_code_detail": http.client.responses[error_code]
                   },
                   clear_text=True)
        if message:
            self.write(""
                       "    <div>%(message)s</div>" % {
                           "message": ensure_str(message)})

        self.write(""
                   "</body>"
                   "</html>")

    async def head(self, *args, **kwargs):
        get_return_text = await self.get(*args, **kwargs)
        if self.status_code != 200:
            return
        if self._written is True:
            self.set_header("content-length", str(len(self._response_body)))
        else:
            self.set_header("content-length", str(len(get_return_text)))
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
        if self._request_handled:
            return

        self._request_handled = True
        try:
            if self.method not in SUPPORTED_METHODS:
                raise HTTPError(400)
            if self.method not in self.allow_methods:
                raise HTTPError(405)
            body = await getattr(self, self.method.lower())(*args, **kwargs)
            if not self._written:
                self.write(body)
        except HTTPError as e:
            traceback.print_exc()
            self.write_error(e.status_code, e.message)
        except Exception as e:
            traceback.print_exc()
            self.write_error(500)
        await self.finish()

    def process_handler(self, body_data):
        if self.http_version == 20:
            pass  # HTTP/2 will be implemented later.
        else:
            self.process_http_v1_handler(body_data)

    def process_http_v1_handler(self, body_data):
        if self._body_parsed:
            return
        if self.method in BODY_EXPECTED_METHODS:
            content_type = self.get_header("content-type")
            content_length = int(self.get_header("content-length"))
            if content_length > MAX_BODY_LENGTH:
                self.write_error(413)  # Body Too Large
                asyncio.ensure_future(self.finish())
                self._body_parsed = True
                return
            self._request_body_data += body_data
            if len(self._request_body_data) < content_length:
                return  # Request Not Completed, wait.
            self._request_body_query = parse_http_v1_body(
                data=self._request_body_data,
                content_type=self.get_header("content-type"),
                content_length=self.get_header("content-length")
            )
            self._body_parsed = True
        else:
            self._body_parsed = True
        asyncio.ensure_future(self.handle(**self.matched_path))


class NotFoundHandler(RequestHandler):
    async def handle(self, *args, **kwargs):
        self.write_error(404)
        await self.finish()


class Application:
    def __init__(self, loop=asyncio.get_event_loop(), **kwargs):
        self.loop = loop
        self.handlers = routes.Mapper()
        if kwargs.get("template_path", None):
            self.template_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(
                    kwargs.get("template_path"),
                    encoding=kwargs.get("encoding", "utf-8")))
        else:
            self.template_env = None

    def make_server(self):
        return (lambda: futurefinity.server.HTTPServer(app=self))

    def listen(self, port, address="127.0.0.1"):
        f = self.loop.create_server(self.make_server(), address, port)
        srv = self.loop.run_until_complete(f)

    def add_handler(self, route_str, name=None):
        def decorator(cls):
            self.handlers.connect(name, route_str, __handler__=cls)
            return cls
        return decorator

    def find_handler(self, path):
        matched_obj = self.handlers.match(path)
        if not matched_obj:
            matched_obj = {"__handler__": NotFoundHandler}
        return matched_obj
