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

import futurefinity
import futurefinity.testutils

import cgi
import json
import http.server

helper = futurefinity.testutils.TestHelper(__file__)

received_body = None


def get_v10_client():
    return futurefinity.client.HTTPClient(
        http_version=10, allow_keep_alive=False)


def get_v11_client():
    return futurefinity.client.HTTPClient()


def make_server_handler(http_version="HTTP/1.0", method="GET",
                        response_by_chunk=False, path="/get_test/"):
    class ServerHandler(http.server.SimpleHTTPRequestHandler):
        def write_http_version(self):
            if self.request_version == "HTTP/1.1":
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")

            else:
                self.send_response(http.server.HTTPStatus.OK)

        def do_GET(self):
            assert method == "GET"

            assert self.request_version == http_version

            assert self.path == path

            self.write_http_version()

            if not response_by_chunk:
                self.send_header("Content-Length", "13")

            else:
                self.send_header("Transfer-Encoding", "Chunked")

            self.send_header("Content-Type", "text/plain")
            self.end_headers()

            if not response_by_chunk:
                self.wfile.write(b"Hello, World!")

            else:
                self.wfile.write(
                    b"7\r\nHello, \r\n6\r\nWorld!\r\n0\r\n\r\n")

        def do_POST(self):
            assert method == "POST"

            assert self.request_version == http_version

            assert self.path == path

            content_type = self.headers.get("Content-Type")
            content_length = self.headers.get("Content-Length")

            if content_type.lower().find("json") == -1:
                body = cgi.FieldStorage(fp=self.rfile, environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": content_length
                })

            else:
                body = json.loads(
                    futurefinity.encoding.ensure_str(
                        self.rfile.read(int(content_length))))

            global received_body
            received_body = body

            self.write_http_version()

            self.send_header("Content-Length", "13")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Hello, World!")

        def log_request(server, *args, **kwargs):
            pass

    return ServerHandler


class ClientGetTestCase:
    @helper.run_until_complete
    async def test_v10_get_request(self):
        ServerHandler = make_server_handler()

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v10_client()

            response = await client.get("http://localhost:8000/get_test/")

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 10, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

    @helper.run_until_complete
    async def test_v11_get_request(self):
        ServerHandler = make_server_handler(
            http_version="HTTP/1.1")

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.get("http://localhost:8000/get_test/")

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

    @helper.run_until_complete
    async def test_v11_get_link_args(self):
        ServerHandler = make_server_handler(
            http_version="HTTP/1.1", path="/get_test/?a=b")

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.get(
                "http://localhost:8000/get_test/", link_args={"a": "b"})

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

    @helper.run_until_complete
    async def test_v11_get_chunked_response(self):
        ServerHandler = make_server_handler("HTTP/1.1", response_by_chunk=True)

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.get("http://localhost:8000/get_test/")

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"


class ClientPostTestCase:
    @helper.run_until_complete
    async def test_post_urlencoded_request(self):
        ServerHandler = make_server_handler(
            http_version="HTTP/1.1", method="POST", path="/post_test/")

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.post("http://localhost:8000/post_test/",
                                         body_args={"a": "b"})

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

        global received_body
        assert received_body is not None

        assert received_body.getfirst("a") == "b"

        received_body = None

    @helper.run_until_complete
    async def test_post_multipart_request(self):
        ServerHandler = make_server_handler(
            http_version="HTTP/1.1", method="POST", path="/post_test/")

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.post(
                "http://localhost:8000/post_test/",
                body_args={"a": "b"},
                headers={"content-type": "multipart/form-data"})

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

        global received_body
        assert received_body is not None

        assert received_body.getfirst("a") == "b"

        received_body = None

    @helper.run_until_complete
    async def test_post_json_request(self):
        ServerHandler = make_server_handler(
            http_version="HTTP/1.1", method="POST", path="/post_test/")

        server = http.server.HTTPServer(("localhost", 8000), ServerHandler)

        try:
            futurefinity.compat.ensure_future(
                helper.loop.run_in_executor(None, server.serve_forever),
                loop=helper.loop)

            client = get_v11_client()

            response = await client.post(
                "http://localhost:8000/post_test/",
                body_args={"a": "b"},
                headers={"content-type": "application/json"})

        finally:
            server.shutdown()
            server.server_close()

        assert response.http_version == 11, "Wrong HTTP Version"
        assert response.status_code == 200, "Wrong Status Code"
        assert response.body == b"Hello, World!"

        global received_body
        assert received_body is not None

        assert received_body.get("a") == "b"

        received_body = None
