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


class UpgradeRequested(httpabc.AbstractEvent):
    @property
    @abc.abstractmethod
    def proposed_protocol(self) -> compat.Text:
        raise NotImplementedError

    @abc.abstractmethod
    async def accept(
        self, headers: Optional[Mapping[compat.Text, compat.Text]]=None
            ) -> streams.AbstractStream:
        raise NotImplementedError


class UpgradeResponded(httpabc.AbstractEvent):
    @property
    @abc.abstractmethod
    def proposed_protocol(self) -> compat.Text:
        raise NotImplementedError

    @abc.abstractmethod
    async def accept(self) -> streams.AbstractStream:
        raise NotImplementedError


class DataReceived(httpabc.AbstractEvent):
    def __init__(self, data: bytes):
        self._data = data

    @property
    def data(self) -> bytes:
        return self._data


class EOFReceived(httpabc.AbstractEvent):
    pass


class BadRequest(httpabc.AbstractEvent):  # HTTPError: 400
    pass


class RequestLengthRequired(httpabc.AbstractEvent):  # HTTPError: 411
    pass


class EntityTooLarge(httpabc.AbstractEvent):  # HTTPError: 413
    pass


class BadResponse(httpabc.AbstractEvent):
    pass
