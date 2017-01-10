#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2017 Futur Solo
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
``futurefinity.client`` contains the `HTTPClient` which implements the
:class:`futurefinity.protocol.HTTPv1Connection` from the client side.

"""

from .utils import cached_property
from . import compat
from . import httpabc
from . import streams
from . import encoding
from . import protocol
from . import httputils
from . import magicdict
from . import multipart
from . import h1connection

from typing import Union, Optional, Mapping, Tuple, Any

import asyncio

import abc
import ssl
import sys
import json
import functools
import traceback
import urllib.parse


class RequestTimeoutError(TimeoutError):
    """
    FutureFinity Client Timeout Error.

    This Error is raised when the server has no response until the timeout.
    """
    pass


class BadResponse(Exception):
    """
    FutureFinity Client Bad Response Error.

    This Error is raised when futurefinity received a bad response from the
    server.
    """
    pass


class ResponseEntityTooLarge(Exception):
    """
    FutureFinity Client Response Entity Too Large Error.

    This Error is raised when futurefinity received a response that entity
    larger than the largest allowed size of entity from the server.
    """
    pass


class HTTPError(Exception):
    def __init__(response: "ClientResponse", *args):
        self._response = response

        if not len(args):
            args = (str(self._response), )

        super().__init__(*args)

    @property
    def response(self) -> "ClientResponse":
        return self._response


class TooManyRedirects(Exception):
    def __init__(request: "ClientRequest", *args):
        self._request = request

        if not len(args):
            args = (str(self._request), )

        super().__init__(*args)

    @property
    def request(self) -> "ClientRequest":
        return self._request


class ClientRequest(httpabc.AbstractHTTPRequest):
    def __init__(
        method: compat.Text, url: compat.Text, *,
        link_args: Optional[Mapping[compat.Text, compat.Text]]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None,
            body: Optional[bytes]=None):
        self._method = method

        self._parsed_url = urllib.parse.urlsplit(url)

        assert self.scheme in ("http", "https"), \
            "URI Scheme must be provided and must be either http or https."

        self._link_args = magicdict.TolerantMagicDict()
        if self._parsed_uri.query:
            self._link_args.update(urllib.parse.parse_qsl(
                self._parsed_url.query, strict_parsing=True))
        if link_args:
            self._link_args.update(link_args)

        self._link_args.freeze()

        self._headers = magicdict.TolerantMagicDict()
        if headers:
            self._headers.update(headers)
        self._headers.freeze()

        assert body is None or isinstance(body, bytes), \
            "Body must be bytes if provided."
        self._body = body

    @property
    def method(self) -> compat.Text:
        return self._method

    @property
    def authority(self) -> compat.Text:
        return self._parsed_url.hostname

    @cached_property
    def port(self) -> int:
        if self._parsed_url.port:
            return self._parsed_url.port

        if self.scheme == "http":
            return 80

        else:  # Scheme can only be either http or https.
            return 443

    @property
    def scheme(self) -> compat.Text:
        return self._parsed_url.scheme

    @cached_property
    def path(self) -> compat.Text:
        return self._parsed_url.path or "/"

    @cached_property
    def uri(self) -> compat.Text:
        return urllib.parse.urlunparse(
            urllib.parse.ParseResult(
                scheme="", netloc="", path=self.link,
                params="", query=urllib.parse.urlencode(self.link_args),
                fragment=""))

    @property
    def link_args(self) -> Mapping[compat.Text, compat.Text]:
        return self._link_args

    @cached_property
    def url(self) -> compat.Text:
        return urllib.parse.urlunparse(
            urllib.parse.ParseResult(
                scheme=self.scheme, netloc=self._parsed_url.netloc,
                path=self.path,
                params=self._parsed_url.params,
                query=urllib.parse.urlencode(self.link_args),
                fragment=self._parsed_url.fragment))

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._headers

    @cached_property
    def _idenifier(self) -> Tuple[compat.Text, int, compat.Text]:
        return (self.authority, self.port, self.scheme)


class ResponseBody(abc.ABC, bytes):
    @property
    @abc.abstractmethod
    def encoding(self) -> Optional[compat.Text]:
        raise NotImplementedError

    @abc.abstractmethod
    def as_str(self, encoding: Optional[compat.Text]=None) -> compat.Text:
        raise NotImplementedError

    @abc.abstractmethod
    def as_json(self, encoding: Optional[compat.Text]=None) -> Any:
        raise NotImplementedError


class _ResponseBody(ResponseBody):
    def __init__(self, *args, _encoding: Optional[compat.Text]=None, **kwargs):
        bytes.__init__(self, *args, **kwargs)
        self._encoding = _encoding

    @property
    def encoding(self) -> Optional[compat.Text]:
        return self._encoding

    def as_str(self, encoding: Optional[compat.Text]=None) -> compat.Text:
        return encoding.ensure_str(
            self, encoding=(encoding or self.encoding or ""))

    def as_json(self, encoding: Optional[compat.Text]=None) -> Any:
        return json.loads(self.as_str(encoding=encoding))


class ClientResponse(httpabc.AbstractHTTPResponse):  # pragma: no cover
    @property
    @abc.abstractmethod
    def http_version(self) -> int:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def request(self) -> ClientRequest:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def body(self) -> ResponseBody:
        raise NotImplementedError


class _ClientResponse(ClientResponse):
    def __init__(
        self, __httpabc_response: httpabc.AbstractHTTPResponse, *,
            http_version: int, request: ClientRequest, body: bytes):
        self._httpabc_response = __httpabc_response

        self._http_version = http_version

        self._request = request

        self._body = body

    @property
    def http_version(self) -> int:
        return self._http_version

    @property
    def status_code(self) -> int:
        return self._httpabc_response.status_code

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._httpabc_response.headers

    @property
    def request(self) -> ClientRequest:
        return self._request

    @cached_property
    def body(self) -> ResponseBody:
        return _ResponseBody(self._body)


def _check_if_transport_closed(transport: asyncio.BaseTransport) -> bool:
    if compat.pyver_satisfies(">=3.5.1"):
        return transport.is_closing()

    try:
        return transport._closing

    except:
        return transport._closed


class HTTPClientConnectionController(protocol.BaseHTTPConnectionController):
    """
    HTTP Client Connection Controller Class.

    THis is a subclass of `protocol.BaseHTTPConnectionController`.

    This is used to control a HTTP Connection from the client side.
    """
    def __init__(self, host: compat.Text, port: int, *args,
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

        if _check_if_transport_closed(self.writer.transport):
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

    async def fetch(self, method: compat.Text, path: compat.Text,
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
                if (not self.writer) or _check_if_transport_closed(
                 self.writer.transport):
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

    Example:
        import asyncio
        import futurefinity

        client = futurefinity.client.HTTPClient()
        fur = client.get("https://www.example.com/")
        response = loop.run_until_complete(fur)

        assert response.status_code == 200
        print(response.body)

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

    def _makeup_url(self, url: compat.Text,
                    link_args: Optional[Mapping[compat.Text, compat.Text]]):
        parsed_url = urllib.parse.urlsplit(url)

        if parsed_url.query:
            if link_args is None:
                link_args = magicdict.TolerantMagicDict()
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

    def _get_connection_controller(
            self, host: compat.Text, port: compat.Text, scheme: compat.Text):
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
        self, method: compat.Text, url: compat.Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[
                    compat.Text, compat.Text]]]=None,
            cookies: Optional[
                Union[httputils.HTTPCookies, Mapping[
                    compat.Text, compat.Text]]]=None,
            link_args: Optional[
                Union[magicdict.TolerantMagicDict, Mapping[
                    compat.Text, compat.Text]]]=None,
            body: Optional[bytes]=None):
        """
        Fetch the request.
        """
        if link_args is not None and not isinstance(
                link_args, magicdict.TolerantMagicDict):
            link_args = magicdict.TolerantMagicDict(link_args)

        url_info = self._makeup_url(url, link_args)
        if not isinstance(headers, protocol.HTTPHeaders):
            if headers is None:
                headers = protocol.HTTPHeaders()
            else:
                headers = protocol.HTTPHeaders(headers)
        if cookies:
            if not isinstance(cookies, httputils.HTTPCookies):
                cookies = httputils.HTTPCookies(cookies)
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
        self, url: compat.Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[
                    compat.Text, compat.Text]]]=None,
            cookies:  Optional[
                Union[httputils.HTTPCookies, Mapping[
                    compat.Text, compat.Text]]]=None,
            link_args:  Optional[
                Union[magicdict.TolerantMagicDict, Mapping[
                    compat.Text, compat.Text]]]=None):
        """
        This is a friendly wrapper of `client.HTTPClient.fetch` for
        `GET` request.
        """
        response = await self.fetch(method="GET", url=url, headers=headers,
                                    cookies=cookies, link_args=link_args)
        return response

    async def post(
        self, url: compat.Text,
            headers: Optional[
                Union[protocol.HTTPHeaders, Mapping[
                    compat.Text, compat.Text]]]=None,
            cookies: Optional[
                Union[httputils.HTTPCookies, Mapping[
                    compat.Text, compat.Text]]]=None,
            link_args: Optional[
                Union[magicdict.TolerantMagicDict, Mapping[
                    compat.Text, compat.Text]]]=None,
            body_args: Optional[
                Union[magicdict.TolerantMagicDict, Mapping[
                    compat.Text, compat.Text]]]=None,
            files: Optional[
                Union[magicdict.TolerantMagicDict, Mapping[
                    compat.Text, compat.Text]]]=None):
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
            body = encoding.ensure_bytes(urllib.parse.urlencode(body_args))

        elif content_type.lower() == "application/json":
            body = encoding.ensure_bytes(json.dumps(body_args))

        elif content_type.lower().startswith("multipart/form-data"):
            multipart_body = multipart.HTTPMultipartBody()
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
