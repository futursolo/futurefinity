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

from typing import Mapping, Optional

from . import compat
from . import streams

import abc


class AbstractHTTPInitial(abc.ABC):
    @property
    @abc.abstractmethod
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        raise NotImplementedError


class AbstractHTTPRequest(AbstractHTTPInitial):
    @property
    @abc.abstractmethod
    def method(self) -> compat.Text:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def link(self) -> compat.Text:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def authority(self) -> compat.Text:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def scheme(self) -> Text:
        raise NotImplementedError


class AbstractHTTPResponse(AbstractHTTPInitial):
    @property
    @abc.abstractmethod
    def status_code(self) -> int:
        raise NotImplementedError


class AbstractHTTPContext(abc.ABC):
    pass


class AbstractEvent(abc.ABC):
    pass


class AbstractHTTPStreamWriter(streams.AbstractStreamWriter):
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

    async def send_response(self, response: AbstractHTTPInitial):
        raise NotImplementedError

    def response_written(self) -> bool:
        raise NotImplementedError


class AbstractHTTPStreamHandler(abc.ABC):
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


class AbstractHTTPConnection(abc.ABC):
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
