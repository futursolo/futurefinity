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

from futurefinity.client import HTTPClient

import asyncio
import unittest
import http.server


class ClientGetTestCollector(unittest.TestCase):
    def make_http_server_handler(self, http_version="HTTP/1.0"):
        class ServerHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(server):
                self.assertEqual(server.request_version, http_version)
                self.assertEqual(server.path, "/get_test/")
                server.send_response(http.server.HTTPStatus.OK)
                server.send_header("Content-Length", "13")
                server.send_header("Content-Type", "text/plain")
                server.end_headers()
                server.wfile.write(b"Hello, World!")

            def log_request(server, *args, **kwargs):
                pass

        return ServerHandler

    def setUp(self):
        self.v10_client = HTTPClient(http_version=10, allow_keep_alive=False)
        self.v11_client = HTTPClient()
        self.loop = asyncio.get_event_loop()

    async def get_coro_result(self, coro):
        self.coro_result = await coro
        self.loop.stop()

    def test_v10_get_request(self):
        ServerHandler = self.make_http_server_handler()
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v10_client.get("http://localhost:8000/get_test/")))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")

    def test_v11_get_request(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1")
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v11_client.get("http://localhost:8000/get_test/")))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")
