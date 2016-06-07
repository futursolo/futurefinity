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
from futurefinity.utils import ensure_str

import cgi
import json
import asyncio
import unittest
import http.server


class ClientGetTestCollector(unittest.TestCase):
    def make_http_server_handler(self, http_version="HTTP/1.0",
                                 has_link_args=False,
                                 response_by_chunk=False):
        class ServerHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(server):
                self.assertEqual(server.request_version, http_version)
                if has_link_args:
                    self.assertEqual(server.path, "/get_test/?a=b")
                else:
                    self.assertEqual(server.path, "/get_test/")
                if response_by_chunk:
                    server.wfile.write(b"HTTP/1.1 200 OK\r\n")
                else:
                    server.send_response(http.server.HTTPStatus.OK)
                if not response_by_chunk:
                    server.send_header("Content-Length", "13")
                else:
                    server.send_header("Transfer-Encoding", "Chunked")
                server.send_header("Content-Type", "text/plain")
                server.end_headers()
                if not response_by_chunk:
                    server.wfile.write(b"Hello, World!")
                else:
                    server.wfile.write(
                        b"7\r\nHello, \r\n6\r\nWorld!\r\n0\r\n\r\n")

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

    def test_v11_get_link_args(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1",
                                                      has_link_args=True)
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v11_client.get("http://localhost:8000/get_test/",
                                    link_args={"a": "b"})))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")

    def test_v11_get_chunked_response(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1",
                                                      response_by_chunk=True)
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


class ClientPostTestCollector(unittest.TestCase):
    def setUp(self):
        self.v11_client = HTTPClient()
        self.loop = asyncio.get_event_loop()

    def make_http_server_handler(self, http_version="HTTP/1.0"):
        class ServerHandler(http.server.SimpleHTTPRequestHandler):
            def do_POST(server):
                content_type = server.headers.get("Content-Type")
                content_length = server.headers.get("Content-Length")
                if content_type.lower().find("json") == -1:
                    body = cgi.FieldStorage(fp=server.rfile, environ={
                        "REQUEST_METHOD": "POST",
                        "CONTENT_TYPE": content_type,
                        "CONTENT_LENGTH": content_length
                    })
                else:
                    body = json.loads(
                        ensure_str(server.rfile.read(int(content_length))))

                self.received_body = body

                server.send_response(http.server.HTTPStatus.OK)
                server.send_header("Content-Length", "13")
                server.send_header("Content-Type", "text/plain")
                server.end_headers()
                server.wfile.write(b"Hello, World!")

            def log_request(server, *args, **kwargs):
                pass

        return ServerHandler

    async def get_coro_result(self, coro):
        self.coro_result = await coro
        self.loop.stop()

    def test_post_urlencoded_request(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1")
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v11_client.post("http://localhost:8000/post_test/",
                                     body_args={"a": "b"})))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")

        body = self.received_body

        self.assertEqual(body.getfirst("a"), "b")

    def test_post_multipart_request(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1")
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v11_client.post(
                    "http://localhost:8000/post_test/",
                    body_args={"a": "b"},
                    headers={"content-type": "multipart/form-data"})))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")

        body = self.received_body

        self.assertEqual(body.getfirst("a"), "b")

    def test_post_json_request(self):
        ServerHandler = self.make_http_server_handler("HTTP/1.1")
        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)
        asyncio.ensure_future(
            self.loop.run_in_executor(None, server.serve_forever))

        asyncio.ensure_future(
            self.get_coro_result(
                self.v11_client.post(
                    "http://localhost:8000/post_test/",
                    body_args={"a": "b"},
                    headers={"content-type": "application/json"})))

        self.loop.run_forever()
        server.shutdown()
        server.server_close()

        response = self.coro_result

        self.assertEqual(response.status_code, 200,
                         "Wrong Status Code")
        self.assertEqual(response.body, b"Hello, World!")

        body = self.received_body

        if hasattr(body, "getfirst"):
            self.assertEqual(body.getfirst("a"), "b")
        else:
            self.assertEqual(body.get("a"), "b")
