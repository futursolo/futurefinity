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

from futurefinity.protocol import TolerantMagicDict
from futurefinity.protocol import HTTPRequest, HTTPResponse

import asyncio

import functools
import urllib.parse


class HTTPClientConnection(asyncio.Protocol):
    """
    HTTPClientConnection Class.
    """
    def __init__(self, request: HTTPRequest, response_future: asyncio.Future,
                 *args, loop: asyncio.BaseEventLoop=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()

        self.transport = None
        self._timeout_handler = None

        self.request = request
        if "user-agent" not in self.request.headers:
            self.request.headers.add("user-agent", "FutureFinity/0.2.0")

        self.response_future = response_future
        self.response = HTTPResponse()
        self._response_finished = False
        self._response_header_finished = False
        self._response_body_finished = False

    def close_timeout_connection(self):
        if self.transport is not None:
            self.transport.close()

        self.response_future.set_exception(Exception)

    def set_timeout_handler(self):
        """
        Set a EventLoop.call_later instance, close transport after timeout.
        """
        self.cancel_timeout_handler()
        self._timeout_handler = self._loop.call_later(
            30, self.close_timeout_connection)

    def cancel_timeout_handler(self):
        """
        Cancel the EventLoop.call_later instance, prevent transport be closed
        accidently.
        """
        if self._timeout_handler is not None:
            self._timeout_handler.cancel()
        self._timeout_handler = None

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(self.request.make_http_v1_request())
        self.set_timeout_handler()

    def data_received(self, data: bytes):
        self.set_timeout_handler()
        try:
            self.http_v1_data_received(data)
        except Exception as e:
            if not (self.response_future.cancelled() or
                    self.response_future.done()):
                self.response_future.set_exception(e)
            self.transport.close()

    def http_v1_data_received(self, data: bytes):
        if self._response_header_finished is False:
            parse_result = self.response.parse_http_v1_response(data)
            if parse_result[0] is False:
                return
            self._response_header_finished = True
            data = parse_result[1]

        if not (self._response_finished or self._response_body_finished):
            self.response.body += data
            content_length = int(
                self.response.headers.get_first("content-length", 0))
            if len(self.response.body) < content_length:
                return
            self.response.body = self.response.body[:content_length]
            self._response_body_finished = True
            self._response_finished = True

        if self._response_finished:
            if not (self.response_future.cancelled() or
                    self.response_future.done()):
                self.response_future.set_result(self.response)
            self.transport.close()

    def connection_lost(self, exc):
        self.cancel_timeout_handler()
        if not self._response_finished:
            if not (self.response_future.cancelled() or
                    self.response_future.done()):
                self.response_future.set_exception(Exception)


class HTTPClient:
    """
    HTTPClient Class.
    """
    def __init__(self, *args, loop: asyncio.BaseEventLoop=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()

    def parse_url(self, url):
        parsed_url = urllib.parse.urlsplit(url)

        if parsed_url.query:
            queries = TolerantMagicDict(
                urllib.parse.parse_qsl(parsed_url.query))
        else:
            queries = TolerantMagicDict()

        return {
            "host": parsed_url.hostname,
            "port": parsed_url.port,
            "scheme": parsed_url.scheme,
            "queries": queries,
            "path": parsed_url.path
        }

    def get(self, url, headers=None, queries=None):
        url_info = self.parse_url(url)
        request = HTTPRequest(host=url_info["host"], port=url_info["port"],
                              path=url_info["path"], scheme=url_info["scheme"])
        if url_info["queries"]:
            request.queries.update(url_info["queries"])
        if headers:
            request.headers.update(headers)
        if queries:
            request.queries.update(queries)

        return self.fetch(request)

    def get(self, url, headers=None, queries=None):
        url_info = self.parse_url(url)
        request = HTTPRequest(host=url_info["host"], port=url_info["port"],
                              path=url_info["path"], scheme=url_info["scheme"])
        if url_info["queries"]:
            request.queries.update(url_info["queries"])
        if headers:
            request.headers.update(headers)
        if queries:
            request.queries.update(queries)

        return self.fetch(request)

    def post(self, url, headers=None, queries=None,
             content_type="application/x-www-form-urlencoded",
             body_fields=None):
        url_info = self.parse_url(url)
        request = HTTPRequest(host=url_info["host"], port=url_info["port"],
                              path=url_info["path"], scheme=url_info["scheme"])
        request.method = "POST"
        if url_info["queries"]:
            request.queries.update(url_info["queries"])
        if headers:
            request.headers.update(headers)
        if queries:
            request.queries.update(queries)

        request.body.set_content_type(content_type)
        if body_fields:
            request.body.update(body_fields)

        return self.fetch(request)

    def fetch(self, request):
        future = asyncio.Future()

        if request.scheme not in ("http", "https"):
            raise Exception("Unknown Protocol Scheme.")

        if request.scheme == "http":
            request.port = 80
        else:
            request.port = 443

        if request.scheme == "https":
            use_ssl = True
        else:
            use_ssl = None

        def connection_callback(conn_future):
            try:
                conn_future.result()
            except Exception as e:
                if future.cancelled() or future.done():
                    return
                future.set_exception(e)

        self._loop.create_task(self._loop.create_connection(
            functools.partial(HTTPClientConnection, request=request,
                              response_future=future, loop=self._loop),
            host=request.host, port=request.port, ssl=use_ssl)
        ).add_done_callback(connection_callback)

        return future
