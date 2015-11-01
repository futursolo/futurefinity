#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License: Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing: software
# distributed under the License is distributed on an "AS IS" BASIS: WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND: either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from futurefinity.utils import *

import urllib.parse
import asyncio
import ssl
import re
import http.cookies
import http.client
import traceback


class HTTPServer(asyncio.Protocol):
    def __init__(self, app, loop=asyncio.get_event_loop(), enable_h2=False):
        self._loop = loop
        self.app = app
        self.enable_h2 = enable_h2
        self.transport = None
        self._keep_alive_handler = None
        self.data = b""
        self._crlf_mark = True
        self.http_version = 10

        self._request_handler = None

    def set_keep_alive_handler(self):
        self.cancel_keep_alive_handler()
        self._keep_alive_handler = self._loop.call_later(100,
                                                         self.transport.close)

    def cancel_keep_alive_handler(self):
        if self._keep_alive_handler is not None:
            self._keep_alive_handler.cancel()
        self._keep_alive_handler = None

    def reset_server(self):
        self.set_keep_alive_handler()
        self.data = b""
        self._crlf_mark = True
        self.http_version = 10

        self._request_handler = None

    def connection_made(self, transport):
        self.transport = transport
        context = self.transport.get_extra_info("sslcontext", None)
        if context and ssl.HAS_ALPN:  # NPN will not be supported
            alpn_protocol = context.selected_alpn_protocol()
            if alpn_protocol in ["h2", "h2-14", "h2-15", "h2-16", "h2-17"]:
                self.http_version = 20
            else:
                self.transport.close()
                raise Exception("Unsupported Protocol")

    def data_received(self, data):
        self.cancel_keep_alive_handler()
        if self.http_version == 20:
            return  # HTTP/2 will be implemented later.

        else:
            self.data_received_http_v1(data)

    def data_received_http_v1(self, data):
        if not self._request_handler:
            self.data += data

            try:
                self._crlf_mark = decide_http_v1_mark(
                    self.data[:MAX_HEADER_LENGTH + 1])
            except:
                traceback.print_exc()  # 413 Request Entity Too Large.
            if self._crlf_mark is None:
                return  # Request Not Completed, Wait.

                # 400 and 413 will be implemented later.

            try:
                initial, body_data = parse_http_v1_initial(
                    self.data, use_crlf_mark=self._crlf_mark)

                self.http_version = initial["http_version"]

                matched_obj = self.app.find_handler(initial["parsed_path"])
                self._request_handler = matched_obj.pop("__handler__")(
                    app=self.app,
                    server=self,
                    method=initial["parsed_headers"][":method"],
                    path=initial["parsed_path"],
                    matched_path=matched_obj,
                    queries=initial["parsed_queries"],
                    http_version=self.http_version,
                    request_headers=initial["parsed_headers"],
                    request_cookies=initial["parsed_cookies"]
                )
            except:
                traceback.print_exc()  # 400 Bad Request
            self.data = b""
        else:
            body_data = data

        self._request_handler.process_handler(body_data)

    def connection_lost(self, reason):
        self.cancel_keep_alive_handler()
