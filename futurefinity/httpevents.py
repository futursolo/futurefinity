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


class DataReceived(httpabc.AbstractEvent):
    def __init__(self, data: bytes):
        self._data = data

    @property
    def data(self) -> bytes:
        return self._data


class EOFReceived(httpabc.AbstractEvent):
    pass


class UpgradeRequired(httpabc.AbstractEvent):
    @abc.abstractmethod
    def detach_stream(self) -> streams.AbstractStream:
        """if not self.is_detachable():
            raise InvalidHTTPOperationError(
                "Cannot detach since the connection is not under "
                "a detachable state.")

        tcp_stream, self._tcp_stream = self._tcp_stream, None
        return tcp_stream"""
        raise NotImplementedError


class HTTPStreamClosed(httpabc.AbstractEvent):
    pass


class BadRequest(httpabc.AbstractEvent):
    pass


class BadResponse(httpabc.AbstractEvent):
    pass


class EntityTooLarge(httpabc.AbstractEvent):
    pass
