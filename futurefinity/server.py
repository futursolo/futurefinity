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

"""
``futurefinity.server`` contains the FutureFinity HTTPServer Class used by
FutureFinity Web Application, which can parse http request, initialize
right RequestHandler and make response to client.
"""

from .utils import ensure_str, ensure_bytes, FutureFinityError
from . import protocol

from typing import Optional

import asyncio

import ssl


class ServerError(FutureFinityError):
    """
    FutureFinity Server Error.

    All Errors from FutureFinity Server Side are based on this class.
    """
    pass


class HTTPServer(asyncio.Protocol, protocol.BaseHTTPConnectionController):
    """
    FutureFinity HTTPServer Class.

    :arg allow_keep_alive: Default: `True`. Turn it to `False` if you want to
      disable keep alive connection for `HTTP/1.1`.
    """
    def __init__(self, *args, allow_keep_alive: bool=True, **kwargs):
        asyncio.Protocol.__init__(self)
        protocol.BaseHTTPConnectionController.__init__(self)
        self.transport = None
        self.use_tls = False
        self.connection = None
        self.use_h2 = False

        self.allow_keep_alive = allow_keep_alive

        self.sockname = None
        self.peername = None
        self.direct_receiver = None

        self.default_timeout_length = 10
        self._timeout_handler = None

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        context = self.transport.get_extra_info("sslcontext", None)
        if context:
            self.use_tls = True
            if ssl.HAS_ALPN:  # NPN will not be supported
                alpn_protocol = context.selected_alpn_protocol()
                if alpn_protocol in ("h2", "h2-14", "h2-15", "h2-16", "h2-17"):
                    self.use_h2 = True
                elif alpn_protocol is not None:
                    self.transport.close()
                    raise ServerError("Unsupported Protocol")

        self.sockname = self.transport.get_extra_info("sockname")
        self.peername = self.transport.get_extra_info("peername")

        if self.use_h2:
            self.transport.close()
            raise ServerError("Unsupported Protocol")
        else:
            self.connection = protocol.HTTPv1Connection(
                controller=self, is_client=False, use_tls=self.use_tls,
                sockname=self.sockname, peername=self.peername,
                allow_keep_alive=self.allow_keep_alive)
        self.set_timeout_handler()

    def set_timeout_handler(self):
        self.cancel_timeout_handler()
        self._timeout_handler = self._loop.call_later(
            self.default_timeout_length, self.transport.close)

    def cancel_timeout_handler(self):
        if self._timeout_handler is not None:
            self._timeout_handler.cancel()
        self._timeout_handler = None

    def data_received(self, data: bytes):
        self.connection.data_received(data)

    def connection_lost(self, exc: Optional[tuple]):
        self.connection.connection_lost(exc)
        self.cancel_timeout_handler()
