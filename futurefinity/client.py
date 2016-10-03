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

from .utils import (
    TolerantMagicDict, FutureFinityError, ensure_bytes, Text)
from . import protocol

from typing import Union, Optional, Mapping

import asyncio

import ssl
import sys
import json
import functools
import traceback
import urllib.parse


class ClientError(FutureFinityError):
    """
    FutureFinity Client Error.

    All Errors from FutureFinity Client Side are based on this class.
    """
    pass


class RequestTimeoutError(ClientError, TimeoutError):
    """
    FutureFinity Client Timeout Error.

    This Error is raised when the server has no response until the timeout.
    """
    pass


class BadResponse(ClientError):
    """
    FutureFinity Client Bad Response Error.

    This Error is raised when futurefinity received a bad response from the
    server.
    """
    pass


class ResponseEntityTooLarge(ClientError):
    """
    FutureFinity Client Response Entity Too Large Error.

    This Error is raised when futurefinity received a response that entity
    larger than the largest allowed size of entity from the server.
    """
    pass


class HTTPClientConnectionController(protocol.BaseHTTPConnectionController):
    """
    HTTP Client Connection Controller Class.

    THis is a subclass of `protocol.BaseHTTPConnectionController`.

    This is used to control a HTTP Connection.
    """
    def __init__(self, host: Text, port: int, *args,
                 allow_keep_alive: bool=True,
                 http_version: int=11,
                 loop: Optional[asyncio.BaseEventLoop]=None,
                 context: ssl.SSLContext=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        self.http_version = http_version
        self.allow_keep_alive = allow_keep_alive

        protocol.BaseHTTPConnectionController.__init__(self)

        self.port = port
        self.host = host
        self.context = context

        self.reader = None
        self.writer = None
        self.connection = None
        self.incoming = None
        self._exc = None

        self.default_timeout_length = 10
        self._timeout_handler = None

    def error_received(
     self, incoming: Optional[protocol.HTTPIncomingResponse],
     exc: tuple):
        if isinstance(tuple[1], protocol.ConnectionEntityTooLarge):
            self._exc = ResponseEntityTooLarge(str(tuple[1]))
        else:
            self._exc = BadResponse(str(tuple[1]))
        self.close_stream_and_connection()

    def message_received(self, incoming: protocol.HTTPIncomingResponse):
        self.incoming = incoming

    async def get_stream_and_connection_ready(self):
        """
        Prepare the Stream and the Connection for new request.
        """
        self.cancel_timeout_handler()
        async def _create_new_stream_and_connection():
            self.reader, self.writer = await asyncio.open_connection(
                host=self.host,  port=self.port, ssl=self.context,
                loop=self._loop)
            self.transport = self.writer.transport

            if self.http_version < 20:
                self.connection = protocol.HTTPv1Connection(
                    is_client=True,
                    http_version=self.http_version,
                    allow_keep_alive=self.allow_keep_alive,
                    use_tls=self.context,
                    sockname=self.writer.get_extra_info("sockname"),
                    peername=self.writer.get_extra_info("peername"),
                    controller=self)
            else:
                pass
            self.set_timeout_handler()
        if not (self.reader and self.writer and self.transport):
            await _create_new_stream_and_connection()

        if self.writer.transport.is_closing():
            await _create_new_stream_and_connection()

    def close_stream_and_connection(self):
        """
        Close the Stream and the Connection.
        """
        self.cancel_timeout_handler()
        if self.connection:
            self.connection.connection_lost()
            self.connection = None
        if self.writer:
            self.writer.close()
            self.reader = None
            self.writer = None
            self.transport = None

    def set_timeout_handler(self):
        self.cancel_timeout_handler()
        self._timeout_handler = self._loop.call_later(
            self.default_timeout_length, self.close_stream_and_connection)

    def cancel_timeout_handler(self):
        if self._timeout_handler is not None:
            self._timeout_handler.cancel()
        self._timeout_handler = None

    async def fetch(self, method: Text, path: Text,
                    headers: protocol.HTTPHeaders, body: bytes):
        """
        Fetch the request.
        """
        await self.get_stream_and_connection_ready()
        headers["host"] = self.host
        self.connection.write_initial(
            http_version=self.http_version,
            method=method,
            path=path,
            headers=headers)

        if body:
            self.connection.write_body(body)

        self.connection.finish_writing()
        while True:
            try:
                incoming_data = await asyncio.wait_for(
                    self.reader.read(4096), 60)
            except asyncio.TimeoutError:
                self.close_stream_and_connection()
                raise RequestTimeoutError("Request Timeout.")

            if not incoming_data:
                if (not self.writer) or self.writer.transport.is_closing():
                    self.close_stream_and_connection()
                    raise BadResponse("Unexpected Remote Close.")

            self.connection.data_received(incoming_data)
            if self._exc is not None:
                _exc = self._exc
                self._exc = None
                raise self._exc

            if self.incoming is not None:
                incoming = self.incoming
                self.incoming = None
                self.set_timeout_handler()
                return incoming


class HTTPClient:
    """
    FutureFinity HTTPClient Class.

    This is the HTTPClient Implementation of FutureFinity.
    """
    def __init__(self, *args, http_version=11,
                 allow_keep_alive: bool=True,
                 loop: Optional[asyncio.BaseEventLoop]=None,
                 context: Optional[ssl.SSLContext]=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        self.allow_keep_alive = allow_keep_alive
        self.http_version = http_version

        self.context = context or ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH)

        self._connection_controllers = {}

    def _makeup_url(self, url: Text,
                    link_args: Optional[Mapping[Text, Text]]):
        parsed_url = urllib.parse.urlsplit(url)

        if parsed_url.query:
            if link_args is None:
                link_args = TolerantMagicDict()
            link_args.update(urllib.parse.parse_qsl(parsed_url.query))

        if link_args is not None:
            encoded_link_args = urllib.parse.urlencode(link_args)
        else:
            encoded_link_args = ""

        path = urllib.parse.urlunparse(urllib.parse.ParseResult(
            scheme="", netloc="", path=(parsed_url.path or "/"),
            params="", query=encoded_link_args, fragment=""))

        return {
            "host": parsed_url.hostname,
            "port": parsed_url.port,
            "scheme": parsed_url.scheme,
            "path": path
        }

    def _get_connection_controller(self, host: Text, port: Text, scheme: Text):
        controller_identifier = (host, port, scheme)
        if controller_identifier in self._connection_controllers.keys():
            return self._connection_controllers.pop(controller_identifier)

        if scheme == "https":
            context = self.context
        else:
            context = None

        return HTTPClientConnectionController(
            allow_keep_alive=self.allow_keep_alive,
            http_version=self.http_version,
            host=host, port=port, context=context)

    def _put_connection_controller(self,
                                   controller: HTTPClientConnectionController):
        if controller.context:
            scheme = "https"
        else:
            scheme = "http"
        controller_identifier = (controller.host, controller.port, scheme)
        if controller_identifier in self._connection_controllers.keys():
            return  # Only cache one controller for each identifier.
        self._connection_controllers[controller_identifier] = controller

    async def fetch(
        self, method: Text, url: Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[Text, Text]]]=None,
            cookies: Optional[
                Union[protocol.HTTPCookies, Mapping[Text, Text]]]=None,
            link_args: Optional[
                Union[TolerantMagicDict, Mapping[Text, Text]]]=None,
            body: Optional[bytes]=None):
        """
        Fetch the request.
        """
        if link_args is not None and not isinstance(link_args,
                                                    TolerantMagicDict):
            link_args = TolerantMagicDict(link_args)

        url_info = self._makeup_url(url, link_args)
        if not isinstance(headers, protocol.HTTPHeaders):
            if headers is None:
                headers = protocol.HTTPHeaders()
            else:
                headers = protocol.HTTPHeaders(headers)
        if cookies:
            if not isinstance(cookies, protocol.HTTPCookies):
                cookies = protocol.HTTPCookies(cookies)
            headers.accept_cookies_for_request(cookies)

        if url_info["scheme"] not in ("http", "https"):
            raise ClientError("Unknown Protocol Scheme.")

        if not url_info["port"]:
            if url_info["scheme"] == "http":
                url_info["port"] = 80
            else:
                url_info["port"] = 443

        controller = self._get_connection_controller(
            host=url_info["host"], port=url_info["port"],
            scheme=url_info["scheme"])

        response = await controller.fetch(method=method,
                                          path=url_info["path"],
                                          headers=headers,
                                          body=body)
        self._put_connection_controller(controller)
        return response

    async def get(
        self, url: Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[Text, Text]]]=None,
            cookies:  Optional[
                Union[protocol.HTTPCookies, Mapping[Text, Text]]]=None,
            link_args:  Optional[
                Union[TolerantMagicDict, Mapping[Text, Text]]]=None):
        """
        This is a friendly wrapper of `client.HTTPClient.fetch` for
        `GET` request.
        """
        response = await self.fetch(method="GET", url=url, headers=headers,
                                    cookies=cookies, link_args=link_args)
        return response

    async def post(
        self, url: Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[Text, Text]]]=None,
            cookies: Optional[
                Union[protocol.HTTPCookies, Mapping[Text, Text]]]=None,
            link_args: Optional[
                Union[TolerantMagicDict, Mapping[Text, Text]]]=None,
            body_args: Optional[
                Union[TolerantMagicDict, Mapping[Text, Text]]]=None,
            files: Optional[
                Union[TolerantMagicDict, Mapping[Text, Text]]]=None):
        """
        This is a friendly wrapper of `client.HTTPClient.fetch` for
        `POST` request.
        """
        if headers is None:
            headers = protocol.HTTPHeaders()
        else:
            headers = protocol.HTTPHeaders(headers)

        if "content-type" in headers.keys():
            content_type = headers["content-type"]
            if files:
                if not content_type.lower().startswith("multipart/form-data"):
                    raise ClientError(
                        "Files can only be sent by multipart/form-data")
        else:
            if not files:  # Automatic Content-Type Decision.
                content_type = "application/x-www-form-urlencoded"
            else:
                content_type = "multipart/form-data"

        if content_type.lower() == "application/x-www-form-urlencoded":
            body = ensure_bytes(urllib.parse.urlencode(body_args))

        elif content_type.lower() == "application/json":
            body = ensure_bytes(json.dumps(body_args))

        elif content_type.lower().startswith("multipart/form-data"):
            multipart_body = protocol.HTTPMultipartBody()
            multipart_body.update(body_args)
            if files:
                multipart_body.files.update(files)
            body, content_type = multipart_body.assemble()
        else:
            raise ClientError("Unsupported Content-Type.")

        content_length = str(len(body))
        headers["content-length"] = content_length

        headers["content-type"] = content_type

        response = await self.fetch(method="POST", url=url, headers=headers,
                                    cookies=cookies, link_args=link_args,
                                    body=body)
        return response
