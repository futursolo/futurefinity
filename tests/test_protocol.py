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

from typing import Optional

import futurefinity

import io
import os
import cgi
import json
import email
import pytest
import http.cookies
import urllib.parse
import unittest.mock


class HTTPHeadersTestCase:
    def test_capitalized_http_v1_headers(self):
        capitalize_header = futurefinity.protocol.CapitalizedHTTPv1Headers()

        assert capitalize_header["set-cookie"] == "Set-Cookie"
        assert capitalize_header["SET-COOKIE"] == "Set-Cookie"
        assert capitalize_header["sET-CooKIe"] == "Set-Cookie"
        assert capitalize_header["MY-cUsToM-heAdER"] == "My-Custom-Header"

    def test_http_headers_parse(self):
        test_string = "Header-A: value-a\r\nHeader-B: value-b\r\n"

        headers = futurefinity.protocol.HTTPHeaders.parse(test_string)

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers["header-a"] == "value-a"
        assert headers["header-b"] == "value-b"

    def test_http_headers_assemble(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        headers["header-b"] = "value-b"

        assert headers.assemble() in [
            b"Header-A: value-a\r\nHeader-B: value-b\r\n",
            b"Header-B: value-b\r\nHeader-A: value-a\r\n"]

    def test_http_headers_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"

        assert str(headers) == "HTTPHeaders([('header-a', 'value-a')])"

    def test_http_headers_copy(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        headers["header-b"] = "value-b"

        assert headers.copy() == headers

    def test_http_headers_load_headers_with_dict(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        headers.load_headers({"header-a": "value-c", "header-b": "value-b"})

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers.get_list("header-a") == ["value-a", "value-c"]
        assert headers["header-b"] == "value-b"

    def test_http_headers_load_headers_with_string(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        test_string = "Header-A: value-c\r\nHeader-B: value-b\r\n"
        headers.load_headers(test_string)

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers.get_list("header-a") == ["value-a", "value-c"]
        assert headers["header-b"] == "value-b"

    def test_http_headers_load_headers_with_bytes(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        test_string = b"Header-A: value-c\r\nHeader-B: value-b\r\n"
        headers.load_headers(test_string)

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers.get_list("header-a") == ["value-a", "value-c"]
        assert headers["header-b"] == "value-b"

    def test_http_headers_load_headers_with_list(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"
        headers.load_headers([("header-a", "value-c"),
                              ("header-b", "value-b")])

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers.get_list("header-a") == ["value-a", "value-c"]
        assert headers["header-b"] == "value-b"

    def test_http_headers_load_headers_with_other(self):
        headers = futurefinity.protocol.HTTPHeaders()

        headers["header-a"] = "value-a"

        with pytest.raises(ValueError):
            headers.load_headers(object())

    def test_http_headers_accept_cookies_for_request(self):
        cookies = http.cookies.SimpleCookie()

        cookies["cookie-b"] = "value-b"

        headers = futurefinity.protocol.HTTPHeaders()

        headers["cookie"] = "cookie-a=valuea; "
        headers.accept_cookies_for_request(cookies)

        assert headers["cookie"] == "cookie-a=valuea; cookie-b=value-b; "

    def test_http_headers_accept_cookies_for_response(self):
        cookies = http.cookies.SimpleCookie()

        cookies["cookie-a"] = "value-a"

        headers = futurefinity.protocol.HTTPHeaders()
        headers.accept_cookies_for_response(cookies)

        assert headers["set-cookie"] == "cookie-a=value-a"


class HTTPMultipartTestCase:
    def test_multipart_file_field_init(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        assert file_field.fieldname == "test-field"
        assert file_field.filename == "test.file"

        assert file_field.content == file_content
        assert file_field.content_type == "image/png"

        assert isinstance(
            file_field.headers, futurefinity.protocol.HTTPHeaders)

        assert file_field.encoding == "binary"

    def test_multipart_file_field_string_method(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )
        assert str(file_field) == (
            "HTTPMultipartFileField(filename='test.file', "
            "content_type='image/png', "
            "headers=HTTPHeaders([]), "
            "encoding='binary')")

    def test_multipart_file_field_assemble(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        assembled_bytes = file_field.assemble()
        initial, content = assembled_bytes.split(b"\r\n\r\n", 1)
        headers = futurefinity.protocol.HTTPHeaders.parse(initial + b"\r\n")

        assert file_content == content[:-2]
        assert headers["content-type"] == "image/png"
        assert headers["content-transfer-encoding"] == "binary"
        assert headers["content-disposition"] == (
            "form-data; name=\"test-field\"; filename=\"test.file\"")

    def test_multipart_file_field_copy(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        with pytest.raises(futurefinity.protocol.ProtocolError):
            file_field.copy()

    def test_multipart_body_init(self):
        body = futurefinity.protocol.HTTPMultipartBody(a="b")

        assert "a" in body.keys()
        assert body["a"] == "b"

    def test_multipart_body_parse(self):
        file_content = os.urandom(100)
        body_bytes = b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; \
name=\"normal-field\"\r\n"
        body_bytes += b"\r\n"
        body_bytes += b"hello\r\n"
        body_bytes += b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; name=\"file-field\"; \
filename=\"test.txt\"\r\n"
        body_bytes += b"Content-Type: application/octet-stream\r\n"
        body_bytes += b"Content-Transfer-Encoding: binary\r\n"
        body_bytes += b"\r\n"
        body_bytes += file_content + b"\r\n"
        body_bytes += b"-------as7B98bFk--\r\n"

        with pytest.raises(futurefinity.protocol.ProtocolError):
            futurefinity.protocol.HTTPMultipartBody.parse(
                "any/any; boundary=-----as7B98bFk", body_bytes)

        with pytest.raises(futurefinity.protocol.ProtocolError):
            futurefinity.protocol.HTTPMultipartBody.parse(
                "multipart/form-data", body_bytes)

        body = futurefinity.protocol.HTTPMultipartBody.parse(
            "multipart/form-data; boundary=\"-----as7B98bFk\"", body_bytes)

        assert "normal-field" in body.keys()
        assert body["normal-field"] == "hello"

        assert "file-field" in body.files
        assert body.files["file-field"].content == file_content

    def test_multipart_body_assemble(self):
        file_content = os.urandom(100)

        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="file-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        body = futurefinity.protocol.HTTPMultipartBody()
        body.files.add("file-field", file_field)
        body.add("normal-field", "hello")

        body_bytes, content_type = body.assemble()

        parsed_body = cgi.FieldStorage(fp=io.BytesIO(body_bytes), environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(body_bytes))
        })

        assert parsed_body.getvalue("normal-field") == "hello"
        assert parsed_body.getvalue("file-field") == file_content

    def test_multipart_body_str_method(self):
        body = futurefinity.protocol.HTTPMultipartBody()
        assert isinstance(str(body), str)

    def test_multipart_body_repr_method(self):
        body = futurefinity.protocol.HTTPMultipartBody()
        assert isinstance(repr(body), str)

    def test_multipart_body_copy(self):
        body = futurefinity.protocol.HTTPMultipartBody()

        with pytest.raises(futurefinity.protocol.ProtocolError):
            body.copy()


class HTTPIncomingMessageTestCase:
    def test_is_chunked_body(self):
        class HTTPIncomingMessageMock(
                futurefinity.protocol.HTTPIncomingMessage):
            def __init__(
                self, http_version: int,
                    headers: Optional[futurefinity.protocol.HTTPHeaders]=None):
                self.http_version = http_version
                self.headers = headers or futurefinity.protocol.HTTPHeaders()

        http_10_message = HTTPIncomingMessageMock(10)
        assert http_10_message._is_chunked_body is False

        http_no_header_message = HTTPIncomingMessageMock(11)
        assert http_no_header_message._is_chunked_body is False

        true_header = futurefinity.protocol.HTTPHeaders()
        true_header.add("Transfer-Encoding", "Chunked")
        http_true_header_message = HTTPIncomingMessageMock(11, true_header)
        assert http_true_header_message._is_chunked_body is True

        other_header = futurefinity.protocol.HTTPHeaders()
        other_header.add("Transfer-Encoding", "Any")
        http_other_header_message = HTTPIncomingMessageMock(11, other_header)
        assert http_other_header_message._is_chunked_body is False

    def test_scheme(self):
        class HTTPIncomingMessageMock(
                futurefinity.protocol.HTTPIncomingMessage):
            def __init__(self, pretend_use_tls):
                self.connection = unittest.mock.Mock()
                self.connection.use_tls = pretend_use_tls

        http_message = HTTPIncomingMessageMock(False)
        assert http_message.scheme == "http"

        https_message = HTTPIncomingMessageMock(True)
        assert https_message.scheme == "https"

    def test_expected_content_length(self):
        class HTTPIncomingMessageMock(
                futurefinity.protocol.HTTPIncomingMessage):
            def __init__(self, headers: futurefinity.protocol.HTTPHeaders):
                self.headers = headers

        http_no_header_message = HTTPIncomingMessageMock(
            futurefinity.protocol.HTTPHeaders())
        assert http_no_header_message._expected_content_length == -1

        true_header = futurefinity.protocol.HTTPHeaders()
        true_header.add("Content-Length", "10000")
        http_true_header_message = HTTPIncomingMessageMock(true_header)
        assert http_true_header_message._expected_content_length == 10000

        other_header = futurefinity.protocol.HTTPHeaders()
        other_header.add("Content-Length", "Any")
        http_other_header_message = HTTPIncomingMessageMock(other_header)
        assert http_other_header_message._expected_content_length == -1

    def test_body_expected(self):
        class HTTPIncomingMessageMock(
                futurefinity.protocol.HTTPIncomingMessage):
            def __init__(self, method="GET", chunked=False, content_length=-1):
                self.method = method
                self.http_version = 11
                self.headers = futurefinity.protocol.HTTPHeaders()
                if chunked:
                    self.headers.add("Transfer-Encoding", "Chunked")
                if content_length != -1:
                    self.headers.add("Content-Length", str(content_length))

        head_message = HTTPIncomingMessageMock("HEAD", True, 100)
        assert head_message._body_expected is False

        no_body_message = HTTPIncomingMessageMock("GET", False, -1)
        assert no_body_message._body_expected is False

        chunked_message = HTTPIncomingMessageMock("POST", True, -1)
        assert chunked_message._body_expected is True

        body_message = HTTPIncomingMessageMock("POST", False, 100)
        assert body_message._body_expected is True

    def test_request_init(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        assert incoming.method == "GET"
        assert incoming.origin_path == "/"
        assert incoming.http_version == 10
        assert incoming.headers is headers
        assert incoming.body == b"abcde"
        assert incoming.connection is connection

    def test_request_parse_origin_path(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        incoming._parse_origin_path()

        assert incoming._path == "/test"
        assert incoming._link_args == futurefinity.magicdict.TolerantMagicDict(
            a="b")

    def test_request_cookies(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("cookie", "a=b;")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        assert "a" in incoming.cookies
        assert incoming.cookies["a"].value == "b"

    def test_request_path(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        assert incoming.path == "/test"

    def test_request_host(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("host", "localhost")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        assert incoming.host == "localhost"

    def test_request_link_args(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        assert incoming.link_args == futurefinity.magicdict.TolerantMagicDict(
            a="b")

    def test_request_body_args_with_urlencoded(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/x-www-form-urlencoded")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"a=b", connection=connection)

        assert incoming.body_args == futurefinity.magicdict.TolerantMagicDict(
            a="b")

    def test_request_body_args_with_multipart(self):
        file_content = os.urandom(100)
        body_bytes = b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; \
name=\"normal-field\"\r\n"
        body_bytes += b"\r\n"
        body_bytes += b"hello\r\n"
        body_bytes += b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; name=\"file-field\"; \
filename=\"test.txt\"\r\n"
        body_bytes += b"Content-Type: application/octet-stream\r\n"
        body_bytes += b"Content-Transfer-Encoding: binary\r\n"
        body_bytes += b"\r\n"
        body_bytes += file_content + b"\r\n"
        body_bytes += b"-------as7B98bFk--\r\n"

        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type",
                    "multipart/form-data; boundary=-----as7B98bFk")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=body_bytes, connection=connection)

        assert "normal-field" in incoming.body_args
        assert incoming.body_args["normal-field"] == "hello"

        assert "file-field" in incoming.body_args.files
        assert incoming.body_args.files["file-field"].content == file_content

    def test_request_body_args_with_json(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/json")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=json.dumps({"a": "b"}).encode(),
            connection=connection)

        assert incoming.body_args == {"a": "b"}

    def test_request_body_args_with_other(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/unknown")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        with pytest.raises(futurefinity.protocol.ProtocolError):
            incoming.body_args

    def test_request_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("host", "localhost")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)
        assert str(incoming) == (
            "HTTPIncomingRequest("
            "method='GET', "
            "path='/test', "
            "http_version=10, "
            "host='localhost', "
            "headers=HTTPHeaders([('host', 'localhost')]), "
            "cookies=<SimpleCookie: >, "
            "link_args=TolerantMagicDict([('a', 'b')]), "
            ")")

    def test_response_init(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        assert incoming.status_code == 200
        assert incoming.http_version == 10
        assert incoming.headers is headers
        assert incoming.body == b"abcde"
        assert incoming.connection is connection

    def test_response_cookies(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("set-cookie", "a=b;")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        assert "a" in incoming.cookies
        assert incoming.cookies["a"].value == "b"

    def test_response_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        assert str(incoming) == (
            "HTTPIncomingResponse("
            "status_code=200, "
            "http_version=10, "
            "headers=HTTPHeaders([]), "
            "cookies=<SimpleCookie: >, "
            ")")


class HTTPConnectionControllerTestCase:
    def test_connection_controller(self):
        controller = futurefinity.protocol.BaseHTTPConnectionController()

        assert controller.transport is None
        assert controller.use_stream is False
        assert controller.initial_received(object()) is None

        assert controller.initial_received(object()) is None
        assert controller.set_timeout_handler(0) is None
        assert controller.cancel_timeout_handler() is None

        with pytest.raises(NotImplementedError):
            controller.stream_received(object(), object())

        with pytest.raises(NotImplementedError):
            controller.error_received(object(), object())

        with pytest.raises(NotImplementedError):
            controller.message_received(object())


def create_controller():
    class ControllerMock(futurefinity.protocol.BaseHTTPConnectionController):
        def __init__(self, *args, **kwargs):
            self.stored_bytes = b""
            self.transport = unittest.mock.Mock()
            self.transport.write = self._write
            self.transport.close = self._close

            self.initial_received_message = None
            self.stream_received_message = None
            self.error_received_message = None
            self.error_received_exc = None
            self.message_received_message = None
            self.set_timeout_triggered = False
            self.cancel_timeout_triggered = False
            self.transport_close_triggered = False

        def _write(self, data):
            self.stored_bytes += data

        def _close(self, *args, **kwargs):
            self.transport_close_triggered = True

        def initial_received(self, message):
            self.initial_received_message = message

        def error_received(self, message=None, exc=None):
            self.error_received_message = message
            self.error_received_exc = exc

        def message_received(self, message):
            self.message_received_message = message

        def set_timeout_handler(self, suggested_time=None):
            self.set_timeout_triggered = True

        def cancel_timeout_handler(self):
            self.cancel_timeout_triggered = True

        @property
        def use_stream(self):
            return False

    return ControllerMock()


class HTTPv1ConnectionTestCase:
    def test_http_v10_client_get(self):
        controller = create_controller()
        connection = futurefinity.protocol.HTTPv1Connection(
            controller=controller, is_client=True, http_version=10,
            use_tls=False, sockname=("127.0.0.1", 23333),
            peername=("127.0.0.1", 9741), allow_keep_alive=True)

        connection.write_initial(
            http_version=10, method="GET", path="/",
            headers=futurefinity.protocol.HTTPHeaders())
        connection.finish_writing()

        initial, headers = controller.stored_bytes.split(b"\r\n", 1)

        assert initial == b"GET / HTTP/1.0"

        message = email.message_from_bytes(headers)

        assert message.get("Connection") == "Close"

        connection.data_received(b"HTTP/1.0 200 OK\r\n")
        connection.data_received(b"Connection: Close\r\n")
        connection.data_received(b"Content-Length: 13\r\n\r\nHello, World!")

        assert controller.transport_close_triggered is True

        message = controller.message_received_message

        assert message is not None

        assert message.http_version == 10
        assert message.status_code == 200

        assert message.headers.get_first("Connection") == "Close"
        assert message.headers.get_first("Content-Length") == "13"

        assert message.body == b"Hello, World!"

    def test_http_v10_client_post(self):
        controller = create_controller()
        connection = futurefinity.protocol.HTTPv1Connection(
            controller=controller, is_client=True, http_version=10,
            use_tls=False, sockname=("127.0.0.1", 23333),
            peername=("127.0.0.1", 9741), allow_keep_alive=True)

        post_body = urllib.parse.urlencode({"a": "b", "c": "d"})

        connection.write_initial(
            http_version=10, method="POST", path="/",
            headers=futurefinity.protocol.HTTPHeaders())
        connection.write_body(post_body.encode())
        connection.finish_writing()

        initial, headers = controller.stored_bytes.split(b"\r\n", 1)
        assert initial == b"POST / HTTP/1.0"

        message = email.message_from_bytes(headers)
        assert message.get("Connection") == "Close"

        assert message.get_payload() == post_body

        connection.data_received(b"HTTP/1.0 200 OK\r\n")
        connection.data_received(b"Connection: Close\r\n")
        connection.data_received(b"Content-Length: 13\r\n\r\nHello, World!")

        assert controller.transport_close_triggered is True

        message = controller.message_received_message
        assert message is not None

        assert message.http_version == 10
        assert message.status_code == 200

        assert message.headers.get_first("Connection") == "Close"
        assert message.headers.get_first("Content-Length") == "13"

        assert message.body == b"Hello, World!"

    def test_http_v10_client_get_no_server_content_length(self):
        controller = create_controller()
        connection = futurefinity.protocol.HTTPv1Connection(
            controller=controller, is_client=True, http_version=10,
            use_tls=False, sockname=("127.0.0.1", 23333),
            peername=("127.0.0.1", 9741), allow_keep_alive=True)

        connection.write_initial(
            http_version=10, method="GET", path="/",
            headers=futurefinity.protocol.HTTPHeaders())
        connection.finish_writing()

        initial, headers = controller.stored_bytes.split(b"\r\n", 1)
        assert initial == b"GET / HTTP/1.0"

        message = email.message_from_bytes(headers)
        assert message.get("Connection") == "Close"

        connection.data_received(b"HTTP/1.0 200 OK\r\n")
        connection.data_received(b"Connection: Close\r\n\r\n")
        connection.data_received(b"Hello, World!")
        connection.connection_lost()

        message = controller.message_received_message
        assert message is not None

        assert message.http_version == 10
        assert message.status_code == 200

        assert message.headers.get_first("Connection") == "Close"

        assert message.body == b"Hello, World!"

    def test_http_v11_client_get_keep_alive(self):
        controller = create_controller()
        connection = futurefinity.protocol.HTTPv1Connection(
            controller=controller, is_client=True, http_version=11,
            use_tls=False, sockname=("127.0.0.1", 23333),
            peername=("127.0.0.1", 9741), allow_keep_alive=True)

        connection.write_initial(
            http_version=11, method="GET", path="/",
            headers=futurefinity.protocol.HTTPHeaders())
        connection.finish_writing()

        initial, headers = controller.stored_bytes.split(b"\r\n", 1)
        assert initial == b"GET / HTTP/1.1"

        message = email.message_from_bytes(headers)
        assert message.get("Connection") == "Keep-Alive"

        connection.data_received(b"HTTP/1.1 200 OK\r\n")
        connection.data_received(b"Connection: Keep-Alive\r\n")
        connection.data_received(b"Transfer-Encoding: Chunked\r\n\r\n")

        assert controller.initial_received_message is not None

        connection.data_received(b"5\r\n")
        connection.data_received(b"Hello\r\n")
        connection.data_received(b"8\r\n")
        connection.data_received(b", World!\r\n")
        connection.data_received(b"0\r\n\r\n")

        assert controller.set_timeout_triggered is not None

        message = controller.message_received_message

        assert message is not None

        assert message.http_version == 11
        assert message.status_code == 200

        assert message.headers.get_first("Connection") == "Keep-Alive"
        assert message.headers.get_first("Transfer-Encoding") == "Chunked"

        assert message.body == b"Hello, World!"
