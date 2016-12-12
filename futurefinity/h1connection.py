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

from typing import Mapping, Optional, Callable

from .utils import Identifier
from . import compat
from . import httpabc
from . import magicdict

import abc

_DEFAULT_MARK = Identifier()


class H1Request(httpabc.AbstractHTTPRequest):
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


class H1Response(httpabc.AbstractHTTPResponse):
    def __init__(
        self, *, status_code: int,
            headers: Optional[Mapping[Text, Text]]=None):
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
        self, *, idle_timeout: int=10,
        max_initial_length: int=8 * 1024,  # 8K
        allow_keep_alive: bool=True,
        chunk_size: int=10 * 1024  # 10K
            ):
        self._idle_timeout = idle_timeout
        self._max_initial_length = max_initial_length
        self._allow_keep_alive = allow_keep_alive
        self._chunk_size = chunk_size

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


class H1StreamWriter(httpabc.AbstractHTTPStreamWriter):
    @property
    @abc.abstractmethod
    def http_version(self) -> int:
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
    async def send_response(self, response: AbstractHTTPInitial):
        raise NotImplementedError

    @abc.abstractmethod
    def response_written(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def detach_stream(self) -> streams.AbstractStream:
        raise NotImplementedError


class H1Connection(httpabc.AbstractHTTPConnection):
    @property
    @abc.abstractmethod
    def http_version(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def bind_handler(self, handler_factory: Callable[
            [], AbstractHTTPStreamHandler]):
        """
        Bind a handler for incoming stream(s).

        One connection can have at most one handler at the same time.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def send_request(
            self, request: AbstractHTTPRequest) -> AbstractHTTPStreamHandler:
        """
        Send a request.

        This method is only usable on client side.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def handle_until_close(self):
        """
        Handle the connection to stream handler(s) until the connection close.

        A handler must be binded before this method is called.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def closed(self) -> bool:
        """
        Return `True` if the connection is closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        """
        Close the connection.

        This is a graceful shutdown. The connection will be closed until all
        opened stream(s) to be closed gracefully.

        No new stream should be created after this point.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def abort(self):
        """
        Abort the connection. Tear down the connection without waiting all
        opened stream(s) to be closed gracefully.

        No new stream should be created after this point.
        """
        raise NotImplementedError
