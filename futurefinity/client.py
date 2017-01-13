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
from . import httpevents
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

__all__ = ["RequestTimeoutError", "BadResponse", "ResponseEntityTooLarge",
           "HTTPError", "TooManyRedirects", "ClientRequest", "ResponseBody",
           "ClientResponse", "HTTPClient"]


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
                scheme="", netloc="", path=self.path,
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
    def __new__(
        Cls, *args, _encoding: Optional[compat.Text]=None,
            **kwargs) -> ResponseBody:
        return bytes.__new__(Cls, *args, **kwargs)

    def __init__(self, *args, _encoding: Optional[compat.Text]=None, **kwargs):
        self._encoding = _encoding

    @property
    def encoding(self) -> Optional[compat.Text]:
        return self._encoding

    def as_str(self, encoding: Optional[compat.Text]=None) -> compat.Text:
        return encoding.ensure_str(
            self, encoding=(encoding or self.encoding or "utf-8"))

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


class _HTTPClientStreamHandler(httpabc.AbstractHTTPStreamHandler):
    def __init__(self):
        self._request = None

        self._writer = None

        self._httpabc_response = None
        self._body_buf = []
        self._eof = True

        self._response = None
        self._exc = None

        self._fur = None

    def attach_request(self, request: ClientRequest, fur: asyncio.Future):
        assert self._fur is None
        assert self._request is None

        self._request = request
        self._fur = fur

        def check_cancelled(fur: asyncio.Future):
            if fur.cancelled() and not self._writer.closed():
                self._writer.close()

        self._fur.add_done_callback(check_cancelled)

        if self._writer is not None:
            self._writer.write(self._request._body)
            self._writer.write_eof()

        elif self._eof:
            self._fur.set_result(_ClientResponse(
                self._httpabc_response,
                http_version=self._writer.http_version,
                request=self._request, body=b"".join(self._body_buf)))

        elif self._exc is not None:
            self._fur.set_exception(self._exc)

    def stream_created(self, writer: httpabc.AbstractHTTPStreamWriter):
        assert self._writer is None
        self._writer = writer

        if self._request is not None:
            self._writer.write(self._request._body)
            self._writer.write_eof()

    def event_received(self, event: httpabc.AbstractEvent):
        @functools.singledispatch
        def dispatch_event(event: httpabc.AbstractEvent):
            pass

        @dispatch_event.register(httpevents.UnexpectedEOF)
        @dispatch_event.register(httpevents.BadResponse)
        def _(event: Union[httpevents.BadResponse, httpevents.UnexpectedEOF]):
            raise BadResponse

        @dispatch_event.register(httpevents.EntityTooLarge)
        def _(event: httpevents.EntityTooLarge):
            raise ResponseEntityTooLarge

        @dispatch_event.register(httpevents.ResponseReceived)
        def _(event: httpevents.ResponseReceived):
            self._httpabc_response = event.response

        @dispatch_event.register(httpevents.DataReceived)
        def _(event: httpevents.DataReceived):
            self._body_buf.append(event.data)

        @dispatch_event.register(httpevents.EOFReceived)
        def _(event: httpevents.EOFReceived):
            self._eof = True

            if self._fur and not self._fur.done():
                self._fur.set_result(_ClientResponse(
                    self._httpabc_response,
                    http_version=self._writer.http_version,
                    request=self._request, body=b"".join(self._body_buf)))

        dispatch_event(event)

    def stream_closed(self, exc: Optional[BaseException]):
        self._exc = exc
        if self._fur and not self._fur.done():
            self._fur.set_exception(
                self._exc or streams.StreamClosedError("Stream Closed."))


class _HTTPClientConnection:
    def __init__(
        self, identifier: Tuple[compat.Text, int, compat.Text],
        h1_context: h1connection.H1Context, idle_timeout: int,
            tls_context: ssl.SSLContext, loop: asyncio.AbstractEventLoop):
        self._loop = loop

        self._host, self._port, self._scheme = identifier
        self._scheme = self._scheme.strip().lower()

        self._h1_context = h1_context
        self._tls_context = tls_context if self._scheme == "https" else None

        self._http_conn = None

    async def _get_ready(self):
        if (not self._http_conn) or self._http_conn.closed():
            tcp_stream = await streams.open_connection(
                host=self._host, port=self._port,
                ssl=self._tls_context,
                loop=self._loop)

            self._http_conn = h1connection.H1Connection(
                self._h1_context, tcp_stream=tcp_stream,
                handler_factory=_HTTPClientStreamHandler, loop=self._loop)

            await self._http_conn.start_serving()

    async def fetch(
            self, request: ClientRequest) -> compat.Awaitable[ClientResponse]:
        await self._get_ready()

        response_fur = self._loop.create_future()

        handler = await self._http_conn.send_request(
            method=request.method, uri=request.uri,
            authority=request.authority, headers=request.headers)
        handler.attach_request(request, response_fur)

        return await response_fur

    @property
    def identifier(self) -> Tuple[compat.Text, int, compat.Text]:
        return (self._host, self._port, self._scheme)

    def close(self):
        self._http_conn.close()

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

            body = b""

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
