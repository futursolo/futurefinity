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

from typing import Mapping, Optional, Callable, Any

from .utils import Identifier
from . import compat
from . import httpabc
from . import streams
from . import magicdict

import abc
import enum
import asyncio

_DEFAULT_MARK = Identifier()


class _H1Request(httpabc.AbstractHTTPRequest):
    def __init__(
        self, *, method: compat.Text,
        uri: compat.Text, authority: Optional[compat.Text]=None,
        scheme: Optional[compat.Text]=None,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        self._method = method
        self._uri = uri
        self._headers = magicdict.TolerantMagicDict()

        if headers:
            self._headers.update(headers)

        if authority:
            self._headers["host"] = authority

        self._scheme = scheme

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._headers

    @property
    def method(self) -> compat.Text:
        return self._method

    @property
    def uri(self) -> compat.Text:
        return self._uri

    @property
    def authority(self) -> compat.Text:
        authority = self.headers.get("host", _DEFAULT_MARK)

        if authority is not _DEFAULT_MARK:
            return authority

        raise AttributeError("Authority(Host) is not set.")

    @property
    def scheme(self) -> compat.Text:
        """
        This is not mandatory in HTTP/1.1 since the scheme is not included
        in the request initial.
        """
        if self._scheme is None:
            raise AttributeError("Scheme is not set.")

        return self._scheme


class _H1Response(httpabc.AbstractHTTPResponse):
    def __init__(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        self._status_code = status_code
        self._headers = magicdict.TolerantMagicDict()

        if headers:
            self._headers.update(headers)

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._headers

    @property
    def status_code(self) -> int:
        return self._status_code


class H1Context(httpabc.AbstractHTTPContext):
    def __init__(
        self, is_client: bool, *, idle_timeout: int=10,
        max_initial_length: int=8 * 1024,  # 8K
        allow_keep_alive: bool=True,
        chunk_size: int=10 * 1024  # 10K
            ):
        self._is_client = is_client
        self._idle_timeout = idle_timeout
        self._max_initial_length = max_initial_length
        self._allow_keep_alive = allow_keep_alive
        self._chunk_size = chunk_size

    @property
    def is_client(self) -> bool:
        return self._is_client

    @property
    def idle_timeout(self) -> int:
        return self._idle_timeout

    @property
    def max_initial_length(self) -> int:
        return self._max_initial_length

    @property
    def allow_keep_alive(self) -> bool:
        return self._allow_keep_alive

    @property
    def chunk_size(self) -> int:
        return self._chunk_size


class _ActionAfterStreamClosed(enum.Enum):
    close = Identifier()
    keep_alive = Identifier()
    detached = Identifier()


class _H1StreamWriter(httpabc.AbstractHTTPStreamWriter):
    def __init__(
        self, conn: "H1Connection",
            handler: httpabc.AbstractHTTPStreamHandler):
        self._conn = conn
        self._handler = handler

    @property
    @abc.abstractmethod
    def http_version(self) -> int:
        raise NotImplementedError

    @property
    def stream_id(self) -> int:
        """
        A positive stream id means this is a stream over a connection.
        """
        return 1

    @property
    @abc.abstractmethod
    def context(self) -> AbstractHTTPContext:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def request(self) -> AbstractHTTPRequest:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def response(self) -> AbstractHTTPResponse:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def incoming(self) -> AbstractHTTPInitial:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def outgoing(self) -> AbstractHTTPInitial:
        raise NotImplementedError

    @abc.abstractmethod
    async def send_response(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        raise NotImplementedError

    @abc.abstractmethod
    def response_written(self) -> bool:
        raise NotImplementedError

    async def _run_until_close(
        self,
            request: Optional[_H1Request]=None) -> _ActionAfterStreamClosed:
        pass

    @abc.abstractmethod
    def write(self, data: bytes):
        """
        Write the data.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def writelines(self, data: Iterable[bytes]):
        """
        Write a list (or any iterable) of data bytes.

        This is equivalent to call `AbstractStreamWriter.write` on each Element
        that the `Iterable` yields out, but in a more efficient way.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def drain(self):
        """
        Give the underlying implementation a chance to drain the pending data
        out of the internal buffer.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def can_write_eof(self) -> bool:
        """
        Return `True` if an eof can be written to the writer.
        """
        raise NotImplementedError

    def write_eof(self):
        """
        Write the eof.

        If the writer does not support eof(half-closed), it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def eof_written(self) -> bool:
        """
        Return `True` if the eof has been written or
        the writer has been closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def closed(self) -> bool:
        """
        Return `True` if the writer has been closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        """
        Close the writer.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def wait_closed(self):
        """
        Wait the writer to close.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def abort(self):
        """
        Abort the writer without draining out all the pending buffer.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        """
        Return optional stream information.

        If The specific name is not presented and the default is not provided,
        the method should raise a `KeyError`.
        """
        raise NotImplementedError


class _H1ConnectionWriter(httpabc.AbstractHTTPStreamWriter):
    def __init__(self, conn: "H1Connection"):
        self._conn = conn

    @property
    def http_version(self) -> int:
        return self._conn.http_version

    @property
    def stream_id(self) -> int:
        """
        Stream id 0 means this is a connection.
        """
        return 0

    @property
    def context(self) -> AbstractHTTPContext:
        return self._conn.context

    @property
    def request(self) -> AbstractHTTPRequest:
        raise NotImplementedError("Stream 0 has no request.")

    @property
    def response(self) -> AbstractHTTPResponse:
        raise NotImplementedError("Stream 0 has no response.")

    @property
    def incoming(self) -> AbstractHTTPInitial:
        raise NotImplementedError("Stream 0 has no incoming initial.")

    @property
    def outgoing(self) -> AbstractHTTPInitial:
        raise NotImplementedError("Stream 0 has no outgoing initial.")

    async def send_response(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        raise NotImplementedError("You cannot send response from stream 0.")

    def response_written(self) -> bool:
        return False

    @abc.abstractmethod
    def write(self, data: bytes):
        raise NotImplementedError("You cannot write data from stream 0.")

    @abc.abstractmethod
    def writelines(self, data: Iterable[bytes]):
        raise NotImplementedError("You cannot write data from stream 0.")

    async def drain(self):
        if not self._conn._tcp_stream:
            return

        await self._conn._tcp_stream.drain()

    def can_write_eof(self) -> bool:
        return False

    def write_eof(self):
        raise NotImplementedError("You cannot write eof from stream 0.")

    def eof_written(self) -> bool:
        return False

    def closed(self) -> bool:
        return self._conn.closed()

    def close(self):
        self._conn.close()

    @abc.abstractmethod
    async def wait_closed(self):
        """
        Wait the writer to close.
        """
        raise NotImplementedError

    def abort(self):
        self._conn.abort()

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        if default is _DEFUALT_MARK:
            raise KeyError(name)

        return default


class H1Connection(httpabc.AbstractHTTPConnection):
    def __init__(
        self, context: H1Context, tcp_stream: streams.AbstractStream,
        handler_factory: Callable[[], httpabc.AbstractHTTPStreamHandler], *,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        self._loop = loop or asyncio.get_event_loop()
        self._context = context

        self._tcp_stream = tcp_stream

        self._handler_factory = handler_factory

        self._http_version = 11
        self._line_separator = None

        self._running = False
        self._closed = False

        self._conn_handler = None
        self._current_http_stream = None

        self._send_request_fur = None
        self._handler_for_request_fur = None

    @property
    def http_version(self) -> int:
        return self._http_version

    @property
    def context(self) -> H1Context:
        return self._context

    async def send_request(
        self, *, method: compat.Text,
        uri: compat.Text, authority: Optional[compat.Text]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None
            ) -> AbstractHTTPStreamHandler:
        """
        Send a request.

        This method is only usable on client side.
        """
        if not self.context.is_client:
            raise httpabc.InvalidHTTPOperationError(
                "An HTTP server cannot send requests to the remote.")

        assert self._running, "The connection is not being handled."

        if not self._tcp_stream:
                raise httpabc.InvalidHTTPOperationError(
                    "The tcp stream has been "
                    "detached from the connection.")

        if self._tcp_stream.closed():
            self.close()

        if self.closed():
            raise httpabc.InvalidHTTPOperationError(
                "The connection has been closed.")

        if self._current_http_stream is not None:
            raise RuntimeError(
                "HTTP/1.x can only have one stream per connection "
                "at the same time.")

        scheme = "http" if self._tcp_stream.get_extra_info(
            "sslcontext", None) is None else "https"
        request = _H1Request(
            method=method, scheme=scheme, uri=uri, authority=authority,
            headers=headers)

        assert self._send_request_fur is not None and \
            not self._send_request_fur.done()

        self._send_request_fur.set_result(request)

        self._handler_for_request_fur = compat.create_future(self._loop)

        handler = await self._handler_for_request_fur

        return handler

    async def handle_until_close(self):
        assert not self._running, "The connection is being handled."

        try:
            if not self._tcp_stream:
                raise httpabc.InvalidHTTPOperationError(
                    "The tcp stream has been "
                    "detached from the connection.")

            if self._tcp_stream.closed():
                self.close()

            if self.closed():
                raise httpabc.InvalidHTTPOperationError(
                    "The connection has been closed.")

            assert self._conn_handler is None
            assert self._send_request_fur is None
            assert self._current_http_stream is None

            self._conn_handler = self._handler_factory()

            self._conn_handler.stream_created(_H1ConnectionWriter(self))

            while True:
                handler = self._handler_factory()
                self._current_http_stream = _H1StreamWriter(self, handler)

                if self.context.is_client:
                    self._send_request_fur = compat.create_future(self._loop)

                    request = await self._send_request_fur

                    if (self._handler_for_request_fur is not None and
                            not self._handler_for_request_fur.done()):
                        self._handler_for_request_fur.set_result(handler)

                    action = await self._current_http_stream._run_until_close(
                        request)

                else:  # Server Side.
                    action = await self._current_http_stream._run_until_close()

                self._current_http_stream = None

                if action == _ActionAfterStreamClosed.close:
                    self.close()

                elif action == _ActionAfterStreamClosed.detached:
                    self._tcp_stream = None
                    self.close()

                elif action == _ActionAfterStreamClosed.keep_alive:
                    continue

                else:
                    raise RuntimeError("Unknown Action Type.")

        finally:
            self._running = False
            self.close()

    def closed(self) -> bool:
        return self._closed

    def _close_impl(self):
        if self._current_http_stream:
            self._current_http_stream.close()

        if self._conn_handler:
            self._conn_handler.stream_closed(None)

        if self._tcp_stream:
            self._tcp_stream.close()

    def close(self):
        if self.closed():
            return

        self._closed = True

        self._close_impl()

    def abort(self):
        if self.closed():
            return

        self._closed = True

        if self._current_http_stream:
            self._current_http_stream.abort()

        self._close_impl()
