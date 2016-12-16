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

from . import httpabc

import abc


class RequestReceived(httpabc.AbstractEvent):
    def __init__(self, request: httpabc.AbstractHTTPRequest):
        self._request = request

    @property
    def request(self) -> httpabc.AbstractHTTPRequest:
        return self._request


class ResponseReceived(httpabc.AbstractEvent):
    def __init__(self, response: httpabc.AbstractHTTPResponse):
        self._response = response

    @property
    def response(self) -> httpabc.AbstractHTTPResponse:
        return self._response


class UpgradeResponded(httpabc.AbstractEvent):
    @property
    @abc.abstractmethod
    def proposed_protocol(self) -> compat.Text:
        raise NotImplementedError

    @abc.abstractmethod
    async def accept_upgrade(self) -> streams.AbstractStream:
        raise NotImplementedError

    @abc.abstractmethod
    def decline_with_close(self) -> streams.AbstractStream:
        raise NotImplementedError

    @abc.abstractmethod
    def accepted(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def declined(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def handled(self) -> bool:
        raise NotImplementedError


class UpgradeRequested(httpabc.AbstractEvent):
    @property
    @abc.abstractmethod
    def proposed_protocol(self) -> compat.Text:
        raise NotImplementedError

    @abc.abstractmethod
    async def accept_upgrade(
        self, headers: Mapping[compat.Text, compat.Text]
            ) -> streams.AbstractStream:
        """if not self.is_detachable():
            raise InvalidHTTPOperationError(
                "Cannot detach since the connection is not under "
                "a detachable state.")

        tcp_stream, self._tcp_stream = self._tcp_stream, None
        return tcp_stream"""
        raise NotImplementedError

    @abc.abstractmethod
    async def decline_with_400(
            self, headers: Mapping[compat.Text, compat.Text]):
        raise NotImplementedError

    @abc.abstractmethod
    def ignore_and_continue(self):
        raise NotImplementedError

    @abc.abstractmethod
    def accepted(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def declined(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def handled(self) -> bool:
        raise NotImplementedError


class DataReceived(httpabc.AbstractEvent):
    def __init__(self, data: bytes):
        self._data = data

    @property
    def data(self) -> bytes:
        return self._data


class EOFReceived(httpabc.AbstractEvent):
    pass


class BadRequest(httpabc.AbstractEvent):
    pass


class BadResponse(httpabc.AbstractEvent):
    pass


class EntityTooLarge(httpabc.AbstractEvent):
    pass
