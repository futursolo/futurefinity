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

from typing import Mapping, Optional, Callable

from . import compat
from . import streams

import abc
import asyncio


class InvalidHTTPOperationError(Exception):
    """
    This Error is raised when an invalid operation is fired.
    """
    pass


class HTTPConnectionClosedError(Exception):
    """
    This Error is raised when the http connection is closed.
    """
    pass


class AbstractHTTPInitial(abc.ABC):  # pragma: no cover
    @property
    @abc.abstractmethod
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        """
        The headers of the initial.

        This should return an instance of `magicdict.TolerantMagicDict`.
        """
        raise NotImplementedError


class AbstractHTTPRequest(AbstractHTTPInitial):  # pragma: no cover
    @property
    @abc.abstractmethod
    def method(self) -> compat.Text:
        """
        The method of the request.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def uri(self) -> compat.Text:
        """
        The uri of the request.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def authority(self) -> compat.Text:
        """
        The authority of the request.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def scheme(self) -> compat.Text:
        """
        The scheme of the request.
        """
        raise NotImplementedError


class AbstractHTTPResponse(AbstractHTTPInitial):  # pragma: no cover
    @property
    @abc.abstractmethod
    def status_code(self) -> int:
        """
        The status code of the response.
        """
        raise NotImplementedError


class AbstractHTTPContext(abc.ABC):  # pragma: no cover
    """
    The constant context can be shared among multiple connection.
    """
    pass


class AbstractEvent(abc.ABC):  # pragma: no cover
    """
    The event happened on the stream or the connection.
    """
    pass


class AbstractHTTPStreamWriter(
        streams.AbstractStreamWriter):  # pragma: no cover
    """
    The stream writer to help the handler to control the connection.
    """
    @property
    @abc.abstractmethod
    def http_version(self) -> int:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def stream_id(self) -> int:
        """
        The id of the stream.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def context(self) -> AbstractHTTPContext:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def request(self) -> AbstractHTTPRequest:
        """
        The Request of the stream.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def response(self) -> AbstractHTTPResponse:
        """
        The Response of the stream.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def incoming(self) -> AbstractHTTPInitial:
        """
        The incoming intital.

        This always points to the initial received from the remote side.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def outgoing(self) -> AbstractHTTPInitial:
        """
        The outgoing intital.

        This always points to the initial sent from the local side.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def send_response(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        """
        Send a response.

        This method is only usable on server side.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def response_written(self) -> bool:
        """
        Return `True` if the response has been written.
        """
        raise NotImplementedError


class AbstractHTTPStreamHandler(abc.ABC):  # pragma: no cover
    """
    Handler to handle the stream.
    """
    def stream_created(self, writer: AbstractHTTPStreamWriter):
        """
        The stream has been successfully created, this will be called
        with a http stream writer to control the stream.

        **This can be a coroutine.**
        """
        pass

    def event_received(self, event: AbstractEvent):
        """
        Called when an event happened. This can be called for many times
        until the stream close.

        **This can be a coroutine.**
        """
        pass

    def stream_closed(self, exc: Optional[BaseException]):
        """
        Called when the stream closed.

        **This can be a coroutine.**
        """
        pass


class AbstractHTTPConnection(abc.ABC):  # pragma: no cover
    @abc.abstractmethod
    def __init__(
        self, context: AbstractHTTPContext, tcp_stream: streams.AbstractStream,
        handler_factory: Callable[[], AbstractHTTPStreamHandler], *,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def http_version(self) -> int:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def context(self) -> AbstractHTTPContext:
        raise NotImplementedError

    @abc.abstractmethod
    async def send_request(
        self, *, method: compat.Text,
        uri: compat.Text, authority: Optional[compat.Text]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None
            ) -> AbstractHTTPStreamHandler:
        """
        Send a request.

        This method is only usable on client side.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def start_serving(self):
        """
        Start serving the connection.
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
    async def wait_closed(self):
        """
        Wait the connection to close.
        """
        raise NotImplementedError
