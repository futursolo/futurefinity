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
    def __init__(self, app, enable_h2=False):
        self.app = app
        self.enable_h2 = enable_h2
        self.reset_server()

    def reset_server(self):
        self.data = b""
        self._crlf_mark = True
        self.http_version = 10

        self._request_handler = None

        self._header_parsed = False
        self._body_parsed = False
        self._multipart_master = False
        self._multipart_boundary = None
        self._multipart_slave = False
        self.parsed_headers = None
        self.request_cookies = None
        self.parsed_path = None
        self.parsed_queries = None
        self.parsed_body = None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self._printed = False
        context = self.transport.get_extra_info("sslcontext", None)
        if context and ssl.HAS_ALPN:  # NPN will not be supported
            alpn_protocol = context.selected_alpn_protocol()
            if alpn_protocol in ["h2", "h2-14", "h2-15", "h2-16", "h2-17"]:
                self.http_version = 20
            else:
                self.transport.close()
                raise Exception("Unsupported Protocol")

    def data_received(self, data):
        if not self._printed:
            print(data[:20])
            self._printed = True
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

                matched_obj = self.app.find_handler(initial["parsed_path"])
                self._request_handler = matched_obj.pop("__handler__")(
                    app=self.app,
                    make_response=self.make_response,
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

    def make_response(self, status_code,
                      response_headers, response_body):
        if self.http_version == 20:
            return  # HTTP/2 will be implemented later.
        else:
            self.make_http_v1_response(status_code,
                                       response_headers, response_body)

    def make_http_v1_response(self, status_code,
                              response_headers, response_body):
        response_text = b""
        if self.http_version == 10:
            response_text += b"HTTP/1.0 "
        elif self.http_version == 11:
            response_text += b"HTTP/1.1 "

        response_text += (str(status_code)).encode() + b" "

        response_text += http.client.responses[status_code].encode() + b"\r\n"
        for (key, value) in response_headers.get_all():
            response_text += ("%(key)s: %(value)s\r\n" % {
                "key": key, "value": value}).encode()
        response_text += b"\r\n"
        response_text += ensure_bytes(response_body)
        self.transport.write(response_text)
        self.transport.close()
