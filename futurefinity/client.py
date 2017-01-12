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
import collections
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
    def __init__(self, response: "ClientResponse", *args):
        self._response = response

        if not len(args):
            args = (str(self._response), )

        super().__init__(*args)

    @property
    def response(self) -> "ClientResponse":
        return self._response


class TooManyRedirects(Exception):
    def __init__(self, request: "ClientRequest", *args):
        self._request = request

        if not len(args):
            args = (str(self._request), )

        super().__init__(*args)

    @property
    def request(self) -> "ClientRequest":
        return self._request


class ClientRequest(httpabc.AbstractHTTPRequest):
    def __init__(
        self, method: compat.Text, url: compat.Text, *,
        link_args: Optional[Mapping[compat.Text, compat.Text]]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None,
            body: Optional[bytes]=None):
        self._method = method

        self._parsed_url = urllib.parse.urlsplit(url)

        assert self.scheme in ("http", "https"), \
            "URI Scheme must be provided and must be either http or https."

        self._link_args = magicdict.TolerantMagicDict()
        if self._parsed_url.query:
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


class HTTPClientConnectionController:
    def error_received(self, incoming: Any, exc: tuple):
        if isinstance(tuple[1], protocol.ConnectionEntityTooLarge):
            self._exc = ResponseEntityTooLarge(str(tuple[1]))
        else:
            self._exc = BadResponse(str(tuple[1]))
        self.close_stream_and_connection()

    def message_received(self, incoming: Any):
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

    async def fetch(self, method: compat.Text, path: compat.Text,
                    headers: Any, body: bytes):
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


class _HTTPClientConnection:
    def __init__(
        self, identifier: Tuple[compat.Text, int, compat.Text],
        h1_context: h1connection.H1Context, idle_timeout: int,
            tls_context: ssl.SSLContext, loop: asyncio.AbstractEventLoop):
        self._loop = loop

        self._host, self._port, self._scheme = identifier

        self._h1_context = h1_context
        self._tls_context = tls_context

        self._tcp_stream = None

        self._http_stream_handler = None
        self._http_conn = None

    async def get_ready(self):
        raise NotImplementedError

    async def fetch(
            self, request: ClientRequest) -> compat.Awaitable[ClientResponse]:
        raise NotImplementedError

    @property
    def identifier(self) -> Tuple[compat.Text, int, compat.Text]:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def __del__(self):
        self.close()


class HTTPClient:
    """
    The FutureFinity HTTPClient.

    This is the Client-side HTTP Implementation of FutureFinity.

    Example:
        import asyncio
        import futurefinity

        client = futurefinity.client.HTTPClient()
        fur = client.get("https://www.example.com/")
        response = loop.run_until_complete(fur)

        assert response.status_code == 200
        print(response.body)

    """
    def __init__(
        self, *, idle_timeout: int=10,
        max_initial_length: int=8 * 1024,  # 8K
        allow_keep_alive: bool=True,
        chunk_size: int=10 * 1024,  # 10K
        tls_context: Optional[ssl.SSLContext]=None,
        max_connections: int=100,
        max_redirects: int=50,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        self._loop = loop or asyncio.get_event_loop()

        self._conns = collections.OrderedDict()

        self._h1_context = h1connection.H1Context(
            is_client=True, idle_timeout=idle_timeout,
            max_initial_length=max_initial_length,
            allow_keep_alive=allow_keep_alive, chunk_size=chunk_size)

        self._tls_context = tls_context or ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH)

        self._idle_timeout = idle_timeout

        self._max_connections = max_connections
        self._max_redirects = max_redirects

    def _get_conn(
        self, identifier: Tuple[compat.Text, int, compat.Text]
            ) -> _HTTPClientConnection:
        if identifier in self._conns.keys():
            return self._conns.pop(identifier)

        return _HTTPClientConnection(
            identifier=identifier,
            h1_context=self._h1_context, idle_timeout=self._idle_timeout,
            tls_context=self._tls_context, loop=self._loop)

    def _put_conn(self, conn: _HTTPClientConnection):
        while conn.identifier in self._conns.keys():
            self._conns.pop(conn.identifier)

        self._conns[conn.identifier] = conn

        while len(self._conns) > self._max_connections:
            self._conns.popitem()

    async def fetch(
        self, request: ClientRequest, allow_redirects: bool=True,
            raise_error: bool=True) -> ClientResponse:
        conn = self._get_conn(request._idenifier)

        response = await conn.fetch(request)

        self._put_conn(conn)

        if allow_redirects:
            current_response = response
            for i in range(0, self._max_redirects):
                if current_response.status_code in (301, 302, 303):
                    new_request = ClientRequest(
                        method="GET", url=current_response.headers["location"],
                        headers=request.headers)

                elif response.status_code in (307, 308):
                    new_request = ClientRequest(
                        method=request.method,
                        url=current_response.headers["location"],
                        headers=request.headers,
                        body=request.body)

                else:
                    response = current_response
                    break

                current_response = await self.fetch(
                    request=new_request, allow_redirects=False,
                    raise_error=False)

            else:
                raise TooManyRedirects(request)

        if raise_error:
            if response.status_code >= 400:
                raise HTTPError(response)

        return response

    def request(
        self, method: compat.Text, url: compat.Text, *,
        link_args: Optional[Mapping[compat.Text, compat.Text]]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None,
        body_args: Optional[Mapping[compat.Text, compat.Text]]=None,
        files: Optional[
            Mapping[compat.Text, multipart.HTTPMultipartFileField]]=None,
            **kwargs) -> compat.Awaitable[ClientResponse]:
        final_headers = magicdict.TolerantMagicDict()
        if headers:
            final_headers.update(headers)

        if files:  # multipart/form-data.
            multipart_body = multipart.HTTPMultipartBody()
            if body_args:
                multipart_body.update(body_args)

            multipart_body.files.update(files)
            body, final_headers["content-type"] = multipart_body.assemble()

            final_headers["content-length"] = encoding.ensure_str(
                len(body))

        elif body_args:  # application/x-www-form-urlencoded.
            final_headers["content-type"] = "application/x-www-form-urlencoded"
            body = encoding.ensure_bytes(
                urllib.parse.urlencode(body_args), encoding="utf-8")

            final_headers["content-length"] = encoding.ensure_str(
                len(body))

        else:
            if "content-type" in final_headers:
                del final_headers["content-type"]

            if "content-length" in final_headers:
                del final_headers["content-length"]

        request = ClientRequest(
            method=method, url=url, link_args=link_args, headers=headers,
            body=body)

        return self.fetch(request, **kwargs)

    def head(self, url: compat.Text, **kwargs
             ) -> compat.Awaitable[ClientResponse]:
        kwargs.setdefault("allow_redirects", False)
        return self.request(method="HEAD", url=url, **kwargs)

    def get(self, url: compat.Text, **kwargs
            ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="GET", url=url, **kwargs)

    def post(self, url: compat.Text, **kwargs
             ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="POST", url=url, **kwargs)

    def delete(self, url: compat.Text, **kwargs
               ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="DELETE", url=url, **kwargs)

    def patch(self, url: compat.Text, **kwargs
              ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="PATCH", url=url, **kwargs)

    def put(self, url: compat.Text, **kwargs
            ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="PUT", url=url, **kwargs)

    def options(self, url: compat.Text, **kwargs
                ) -> compat.Awaitable[ClientResponse]:
        return self.request(method="OPTIONS", url=url, **kwargs)

    def __del__(self):
        if hasattr(self, "_conns"):
            while (self._conns):  # Destroy all the connections.
                _, conn = self._conns.popitem()
                conn.close()


def fetch(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().fetch(*args, **kwargs)


def get(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().get(*args, **kwargs)


def post(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().post(*args, **kwargs)


def delete(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().delete(*args, **kwargs)


def patch(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().patch(*args, **kwargs)


def put(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().put(*args, **kwargs)


def options(*args, **kwargs) -> compat.Awaitable[ClientResponse]:
    return HTTPClient().options(*args, **kwargs)
