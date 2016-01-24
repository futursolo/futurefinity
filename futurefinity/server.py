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

"""
``futurefinity.server`` contains the FutureFinity HTTPServer Class used by
FutureFinity Web Application, which can parse http request, initialize
right RequestHandler and make response to client.
"""

from futurefinity.utils import ensure_str, ensure_bytes
from futurefinity.protocol import HTTPHeaders, HTTPRequest, HTTPError

import futurefinity

import asyncio

import re
import cgi
import ssl
import typing
import traceback
import http.client
import http.cookies
import urllib.parse


class HTTPServer(asyncio.Protocol):
    """
    FutureFinity HTTPServer Class.

    Generally, this class should not be used directly in your application.
    If you want customize server before pass it event loop, call::

      app.make_server()

    The make_server() function will return a lambda warpped HTTPServer
    instance, which can pass right Application Instance and Application
    Configuration to server.
    """
    def __init__(self, app, loop=asyncio.get_event_loop(),
                 enable_h2: bool=False):
        self._loop = loop
        self.app = app
        self.enable_h2 = enable_h2

        self.transport = None
        self._keep_alive_handler = None

        self._request_parser = None
        self._request_finished = False

        self.http_version = 10

        self._request_handlers = {}

    def set_keep_alive_handler(self):
        """
        Set a EventLoop.call_later instance, close transport after timeout.
        """
        self.cancel_keep_alive_handler()
        self._keep_alive_handler = self._loop.call_later(100,
                                                         self.transport.close)

    def cancel_keep_alive_handler(self):
        """
        Cancel the EventLoop.call_later instance, prevent transport be closed
        accidently.
        """
        if self._keep_alive_handler is not None:
            self._keep_alive_handler.cancel()
        self._keep_alive_handler = None

    def reset_server(self):
        """
        Reset the server, make the server able to receive new request in a
        connection.
        """
        self._request_handlers = {}
        self.set_keep_alive_handler()

        self._request_parser = None
        self._request_finished = False

    def connection_made(self, transport: asyncio.BaseTransport):
        """
        Called by Event Loop when the connection is made.
        """
        self.transport = transport
        context = self.transport.get_extra_info("sslcontext", None)
        if context and ssl.HAS_ALPN:  # NPN will not be supported
            alpn_protocol = context.selected_alpn_protocol()
            if alpn_protocol in ["h2", "h2-14", "h2-15", "h2-16", "h2-17"]:
                self.http_version = 20
            else:
                self.transport.close()
                raise Exception("Unsupported Protocol")

    def handle_request_error(self, e: Exception):
        """
        Response an HTTPError when a error is raised when parsing an HTTP
        Request.
        """
        if self.http_version == 20:
            return  # HTTP/2 will be implemented later.
        else:
            self.handle_request_error_http_v1(e)

    def handle_request_error_http_v1(self, e: Exception):
        """
        Response an HTTP/1.x Error.

        This function should not be used directly, handle_request_error()
        function will pass it to the right http version.
        """
        status_code = 400
        message = None
        if isinstance(e, HTTPError):
            status_code = e.status_code
            message = e.message

        response_body = ensure_bytes(status_code) + b": "
        response_body += ensure_bytes(http.client.responses[status_code])

        response_text = b""

        if self.http_version == 11:
            response_text += b"HTTP/1.1 "
        else:
            response_text += b"HTTP/1.0 "

        response_text += ensure_bytes(status_code) + b" "

        response_text += ensure_bytes(http.client.responses[
            status_code]) + b"\r\n"

        response_text += b"Content-Type: text/plain\r\n"

        response_text += b"Content-Length: %d\r\n" % len(response_body)

        response_text += b"\r\n\r\n"

        response_text += response_body

        self.transport.write(response_text)
        self.transport.close()

    def data_received(self, data: bytes):
        """
        Called by Event Loop when data received.
        """
        self.cancel_keep_alive_handler()
        try:
            if self.http_version == 20:
                return  # HTTP/2 will be implemented later.
            else:
                self.http_v1_data_received(data)
        except Exception as e:
            if self.app.settings.get("debug", False):
                traceback.print_exc()
            self.handle_request_error(e)

    def http_v1_data_received(self, data: bytes):
        if self._request_finished:
            return

        if self._request_parser is None:
            self._request_parser = HTTPRequest()

        self._request_finished = self._request_parser.parse_http_v1_request(
            data)
        self.http_version = self._request_parser.http_version

        if self._request_finished:
            self._request_handlers[0] = asyncio.ensure_future(
                self.handle_request(self._request_parser))

    async def handle_request(self, request: HTTPRequest):
        """
        Handle an HTTP Request to Right RequestHandler.
        """
        matched_obj = self.app.find_handler(request.path)
        request_handler = matched_obj.pop("__handler__")(
            app=self.app,
            server=self,
            request=request,
            make_response=self.make_response
        )
        await request_handler.handle(**matched_obj)

    def make_response(self, status_code: int,
                      response_headers: HTTPHeaders,
                      response_body: bytes):
        """
        Make http response to client.
        """
        if self.http_version == 20:
            pass  # HTTP/2 will be implemented later.
        else:
            self.make_http_v1_response(status_code, response_headers,
                                       response_body)

    def make_http_v1_response(
        self,
        status_code: int,
        response_headers: HTTPHeaders,
        response_body: bytes):

        """
        Make HTTP/1.x response to client.

        This function should not be called directly, make_response() function
        will handle it to right http version.
        """
        response_text = b""
        if self.http_version == 10:
            response_text += b"HTTP/1.0 "
        elif self.http_version == 11:
            response_text += b"HTTP/1.1 "

        response_text += ensure_bytes(str(status_code)) + b" "

        response_text += ensure_bytes(http.client.responses[
            status_code]) + b"\r\n"
        for (key, value) in response_headers.get_all():
            response_text += ensure_bytes("%(key)s: %(value)s\r\n" % {
                "key": key, "value": value})
        response_text += b"\r\n"
        response_text += ensure_bytes(response_body)
        self.transport.write(response_text)
        if self.http_version == 11 and self.app.settings.get(
         "allow_keep_alive", True):
            self.reset_server()
        else:
            self.transport.close()

    def connection_lost(self, reason: typing.Union[str, bytes]):
        """
        Called by Event Loop when the connection lost.
        """
        self.cancel_keep_alive_handler()
        for (key, value) in self._request_handlers.items():
            value.cancel()
