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

from futurefinity.utils import TolerantMagicDict

from typing import Optional

import futurefinity.protocol

import io
import os
import cgi
import sys
import json
import email
import unittest
import http.cookies
import unittest.mock


class HTTPHeadersTestCollector(unittest.TestCase):
    def test_capitalized_http_v1_headers(self):
        capitalize_header = futurefinity.protocol.CapitalizedHTTPv1Headers()
        self.assertEqual(capitalize_header["set-cookie"], "Set-Cookie")
        self.assertEqual(capitalize_header["SET-COOKIE"], "Set-Cookie")
        self.assertEqual(capitalize_header["sET-CooKIe"], "Set-Cookie")
        self.assertEqual(capitalize_header["MY-cUsToM-heAdER"],
                         "My-Custom-Header")

    def test_http_headers_parse(self):
        test_string = "Header-A: value-a\r\nHeader-B: value-b\r\n"
        headers = futurefinity.protocol.HTTPHeaders.parse(test_string)
        self.assertEqual(set(headers.keys()), set(["header-a", "header-b"]))
        self.assertEqual(headers["header-a"], "value-a")
        self.assertEqual(headers["header-b"], "value-b")

    def test_http_headers_assemble(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        headers["header-b"] = "value-b"
        self.assertIn(headers.assemble(),
                      [b"Header-A: value-a\r\nHeader-B: value-b\r\n",
                       b"Header-B: value-b\r\nHeader-A: value-a\r\n"])

    def test_http_headers_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        self.assertEqual(str(headers),
                         "HTTPHeaders([('header-a', 'value-a')])")

    def test_http_headers_copy(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        headers["header-b"] = "value-b"
        self.assertEqual(headers.copy(), headers)

    def test_http_headers_load_headers_with_dict(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        headers.load_headers({"header-a": "value-c", "header-b": "value-b"})
        self.assertEqual(set(headers.keys()), set(["header-a", "header-b"]))
        self.assertEqual(headers.get_list("header-a"), ["value-a", "value-c"])
        self.assertEqual(headers["header-b"], "value-b")

    def test_http_headers_load_headers_with_string(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        test_string = "Header-A: value-c\r\nHeader-B: value-b\r\n"
        headers.load_headers(test_string)
        self.assertEqual(set(headers.keys()), set(["header-a", "header-b"]))
        self.assertEqual(headers.get_list("header-a"), ["value-a", "value-c"])
        self.assertEqual(headers["header-b"], "value-b")

    def test_http_headers_load_headers_with_bytes(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        test_string = b"Header-A: value-c\r\nHeader-B: value-b\r\n"
        headers.load_headers(test_string)
        self.assertEqual(set(headers.keys()), set(["header-a", "header-b"]))
        self.assertEqual(headers.get_list("header-a"), ["value-a", "value-c"])
        self.assertEqual(headers["header-b"], "value-b")

    def test_http_headers_load_headers_with_list(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        headers.load_headers([("header-a", "value-c"),
                              ("header-b", "value-b")])
        self.assertEqual(set(headers.keys()), set(["header-a", "header-b"]))
        self.assertEqual(headers.get_list("header-a"), ["value-a", "value-c"])
        self.assertEqual(headers["header-b"], "value-b")

    def test_http_headers_load_headers_with_other(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers["header-a"] = "value-a"
        self.assertRaises(ValueError, headers.load_headers, object())

    def test_http_headers_accept_cookies_for_request(self):
        cookies = http.cookies.SimpleCookie()
        cookies["cookie-b"] = "value-b"
        headers = futurefinity.protocol.HTTPHeaders()
        headers["cookie"] = "cookie-a=valuea; "
        headers.accept_cookies_for_request(cookies)
        self.assertEqual(
            headers["cookie"], "cookie-a=valuea; cookie-b=value-b; ")

    def test_http_headers_accept_cookies_for_response(self):
        cookies = http.cookies.SimpleCookie()
        cookies["cookie-a"] = "value-a"
        headers = futurefinity.protocol.HTTPHeaders()
        headers.accept_cookies_for_response(cookies)
        self.assertEqual(headers["set-cookie"], "cookie-a=value-a")


class HTTPMultipartTestCollector(unittest.TestCase):
    def test_multipart_file_field_init(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        self.assertEqual(file_field.fieldname, "test-field")
        self.assertEqual(file_field.filename, "test.file")
        self.assertEqual(file_field.content, file_content)
        self.assertEqual(file_field.content_type, "image/png")
        self.assertIsInstance(file_field.headers,
                              futurefinity.protocol.HTTPHeaders)
        self.assertEqual(file_field.encoding, "binary")

    def test_multipart_file_field_string_method(self):
        file_content = os.urandom(100)
        file_field = futurefinity.protocol.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )
        self.assertEqual(
            str(file_field),
            ("HTTPMultipartFileField(filename='test.file', "
             "content_type='image/png', "
             "headers=HTTPHeaders([]), "
             "encoding='binary')"))

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

        self.assertEqual(file_content, content[:-2])
        self.assertEqual(headers["content-type"], "image/png")
        self.assertEqual(headers["content-transfer-encoding"], "binary")
        self.assertEqual(
            headers["content-disposition"],
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

        self.assertRaises(futurefinity.protocol.ProtocolError,
                          file_field.copy)

    def test_multipart_body_init(self):
        body = futurefinity.protocol.HTTPMultipartBody(a="b")
        self.assertIn("a", body.keys())
        self.assertEqual(body["a"], "b")

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

        self.assertRaises(futurefinity.protocol.ProtocolError,
                          futurefinity.protocol.HTTPMultipartBody.parse,
                          "any/any; boundary=-----as7B98bFk", body_bytes)

        self.assertRaises(futurefinity.protocol.ProtocolError,
                          futurefinity.protocol.HTTPMultipartBody.parse,
                          "multipart/form-data", body_bytes)

        body = futurefinity.protocol.HTTPMultipartBody.parse(
            "multipart/form-data; boundary=\"-----as7B98bFk\"",
            body_bytes)

        self.assertIn("normal-field", body)
        self.assertEqual(body["normal-field"], "hello")

        self.assertIn("file-field", body.files)
        self.assertEqual(body.files["file-field"].content, file_content)

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
        self.assertEqual(parsed_body.getvalue("normal-field"), "hello")
        self.assertEqual(parsed_body.getvalue("file-field"), file_content)

    def test_multipart_body_str_method(self):
        body = futurefinity.protocol.HTTPMultipartBody()
        self.assertIsInstance(str(body), str)

    def test_multipart_body_repr_method(self):
        body = futurefinity.protocol.HTTPMultipartBody()
        self.assertIsInstance(repr(body), str)

    def test_multipart_body_copy(self):
        body = futurefinity.protocol.HTTPMultipartBody()
        self.assertRaises(futurefinity.protocol.ProtocolError,
                          body.copy)


class HTTPIncomingMessageTestCollector(unittest.TestCase):
    def test_is_chunked_body(self):
        class HTTPIncomingMessageMock(
         futurefinity.protocol.HTTPIncomingMessage):
            def __init__(mock, http_version: int,
                         headers: Optional[
                            futurefinity.protocol.HTTPHeaders]=None):
                mock.http_version = http_version
                mock.headers = headers or futurefinity.protocol.HTTPHeaders()

        http_10_message = HTTPIncomingMessageMock(10)
        self.assertFalse(http_10_message._is_chunked_body)

        http_no_header_message = HTTPIncomingMessageMock(11)
        self.assertFalse(http_no_header_message._is_chunked_body)

        true_header = futurefinity.protocol.HTTPHeaders()
        true_header.add("Transfer-Encoding", "Chunked")
        http_true_header_message = HTTPIncomingMessageMock(11, true_header)
        self.assertTrue(http_true_header_message._is_chunked_body)

        other_header = futurefinity.protocol.HTTPHeaders()
        other_header.add("Transfer-Encoding", "Any")
        http_other_header_message = HTTPIncomingMessageMock(11, other_header)
        self.assertFalse(http_other_header_message._is_chunked_body)

    def test_scheme(self):
        class HTTPIncomingMessageMock(
         futurefinity.protocol.HTTPIncomingMessage):
            def __init__(mock, pretend_use_tls):
                mock.connection = unittest.mock.Mock()
                mock.connection.use_tls = pretend_use_tls

        http_message = HTTPIncomingMessageMock(False)
        self.assertEqual(http_message.scheme, "http")

        https_message = HTTPIncomingMessageMock(True)
        self.assertEqual(https_message.scheme, "https")

    def test_expected_content_length(self):
        class HTTPIncomingMessageMock(
         futurefinity.protocol.HTTPIncomingMessage):
            def __init__(mock, headers: futurefinity.protocol.HTTPHeaders):
                mock.headers = headers

        http_no_header_message = HTTPIncomingMessageMock(
            futurefinity.protocol.HTTPHeaders())
        self.assertEqual(http_no_header_message._expected_content_length, -1)

        true_header = futurefinity.protocol.HTTPHeaders()
        true_header.add("Content-Length", "10000")
        http_true_header_message = HTTPIncomingMessageMock(true_header)
        self.assertEqual(
            http_true_header_message._expected_content_length, 10000)

        other_header = futurefinity.protocol.HTTPHeaders()
        other_header.add("Content-Length", "Any")
        http_other_header_message = HTTPIncomingMessageMock(other_header)
        self.assertEqual(
            http_other_header_message._expected_content_length, -1)

    def test_body_expected(self):
        class HTTPIncomingMessageMock(
         futurefinity.protocol.HTTPIncomingMessage):
            def __init__(mock, method="GET", chunked=False, content_length=-1):
                mock.method = method
                mock.http_version = 11
                mock.headers = futurefinity.protocol.HTTPHeaders()
                if chunked:
                    mock.headers.add("Transfer-Encoding", "Chunked")
                if content_length != -1:
                    mock.headers.add("Content-Length", str(content_length))

        head_message = HTTPIncomingMessageMock("HEAD", True, 100)
        self.assertFalse(head_message._body_expected)

        no_body_message = HTTPIncomingMessageMock("GET", False, -1)
        self.assertFalse(no_body_message._body_expected)

        chunked_message = HTTPIncomingMessageMock("POST", True, -1)
        self.assertTrue(chunked_message._body_expected)

        body_message = HTTPIncomingMessageMock("POST", False, 100)
        self.assertTrue(body_message._body_expected)

    def test_request_init(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        self.assertEqual(incoming.method, "GET")
        self.assertEqual(incoming.origin_path, "/")
        self.assertEqual(incoming.http_version, 10)
        self.assertIs(incoming.headers, headers)
        self.assertEqual(incoming.body, b"abcde")
        self.assertIs(incoming.connection, connection)

    def test_request_parse_origin_path(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        incoming._parse_origin_path()

        self.assertEqual(incoming._path, "/test")
        self.assertEqual(incoming._link_args, TolerantMagicDict(a="b"))

    def test_request_cookies(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("cookie", "a=b;")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        self.assertIn("a", incoming.cookies)
        self.assertEqual(incoming.cookies["a"].value, "b")

    def test_request_path(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        self.assertEqual(incoming.path, "/test")

    def test_request_host(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("host", "localhost")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        self.assertEqual(incoming.host, "localhost")

    def test_request_link_args(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        self.assertEqual(incoming.link_args, TolerantMagicDict(a="b"))

    def test_request_body_args_with_urlencoded(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/x-www-form-urlencoded")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"a=b", connection=connection)

        self.assertEqual(incoming.body_args, TolerantMagicDict(a="b"))

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

        self.assertIn("normal-field", incoming.body_args)
        self.assertEqual(incoming.body_args["normal-field"], "hello")

        self.assertIn("file-field", incoming.body_args.files)
        self.assertEqual(incoming.body_args.files["file-field"].content,
                         file_content)

    def test_request_body_args_with_json(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/json")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=json.dumps({"a": "b"}).encode(),
            connection=connection)

        self.assertEqual(incoming.body_args, {"a": "b"})

    def test_request_body_args_with_other(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("Content-Type", "application/unknown")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)

        try:
            args = incoming.body_args
        except Exception as e:
            self.assertEqual(sys.exc_info()[0],
                             futurefinity.protocol.ProtocolError)

    def test_request_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("host", "localhost")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingRequest(
            method="GET", origin_path="/test?a=b", http_version=10,
            headers=headers, body=b"abcde", connection=connection)
        self.assertEqual(
            str(incoming),
            ("HTTPIncomingRequest("
             "method='GET', "
             "path='/test', "
             "http_version=10, "
             "host='localhost', "
             "headers=HTTPHeaders([('host', 'localhost')]), "
             "cookies=<SimpleCookie: >, "
             "link_args=TolerantMagicDict([('a', 'b')]), "
             ")")
        )

    def test_response_init(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        self.assertEqual(incoming.status_code, 200)
        self.assertEqual(incoming.http_version, 10)
        self.assertIs(incoming.headers, headers)
        self.assertEqual(incoming.body, b"abcde")
        self.assertIs(incoming.connection, connection)

    def test_response_cookies(self):
        headers = futurefinity.protocol.HTTPHeaders()
        headers.add("set-cookie", "a=b;")
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        self.assertIn("a", incoming.cookies)
        self.assertEqual(incoming.cookies["a"].value, "b")

    def test_response_str_method(self):
        headers = futurefinity.protocol.HTTPHeaders()
        connection = object()
        incoming = futurefinity.protocol.HTTPIncomingResponse(
            status_code=200, http_version=10, headers=headers,
            body=b"abcde", connection=connection)

        self.assertEqual(
            str(incoming),
            ("HTTPIncomingResponse("
             "status_code=200, "
             "http_version=10, "
             "headers=HTTPHeaders([]), "
             "cookies=<SimpleCookie: >, "
             ")"))


class HTTPConnectionControllerTestCollector(unittest.TestCase):
    def test_connection_controller(self):
        controller = futurefinity.protocol.BaseHTTPConnectionController()
        self.assertIsNone(controller.transport, None)
        self.assertFalse(controller.use_stream, None)
        self.assertIsNone(controller.initial_received(object()), None)
        self.assertIsNone(controller.set_timeout_handler(0), None)
        self.assertIsNone(controller.cancel_timeout_handler(0), None)
        self.assertRaises(NotImplementedError, controller.stream_received,
                          object(), object())
        self.assertRaises(NotImplementedError, controller.error_received,
                          object(), object())
        self.assertRaises(NotImplementedError, controller.message_received,
                          object())


class HTTPv1ConnectionTestCollector(unittest.TestCase):
    def create_controller(self):
        class ControllerMock(
         futurefinity.protocol.BaseHTTPConnectionController):
            def __init__(mock, *args, **kwargs):
                mock.stored_bytes = b""
                mock.transport = unittest.mock.Mock()
                mock.transport.write = mock._write
                mock.transport.close = mock._close

                mock.initial_received_message = None
                mock.stream_received_message = None
                mock.error_received_message = None
                mock.message_received_message = None
                mock.set_timeout_triggered = False
                mock.cancel_timeout_triggered = False
                mock.transport_close_triggered = False

            def _write(mock, data):
                mock.stored_bytes += data

            def _close(mock, *args, **kwargs):
                mock.transport_close_triggered = True

            def message_received(mock, message):
                mock.message_received_message = message

            @property
            def use_stream(self):
                return False

        return ControllerMock()

    def random_bytes_writing(self):
        pass

    def test_http_v10_client_get_no_keep_alive(self):
        controller = self.create_controller()
        connection = futurefinity.protocol.HTTPv1Connection(
            controller=controller, is_client=True, http_version=10,
            use_tls=False, sockname=("127.0.0.1", 23333),
            peername=("127.0.0.1", 9741), allow_keep_alive=False)

        connection.write_initial(
            http_version=10, method="GET", path="/",
            headers=futurefinity.protocol.HTTPHeaders())
        connection.finish_writing()

        initial, headers = controller.stored_bytes.split(b"\r\n", 1)

        self.assertEqual(initial, b"GET / HTTP/1.0")

        message = email.message_from_bytes(headers)

        self.assertEqual(message.get("Connection"), "Close")

        connection.data_received(b"HTTP/1.0 200 OK\r\n")
        connection.data_received(b"Connection: Close\r\n")
        connection.data_received(b"Content-Length: 13\r\n\r\nHello, World!")

        self.assertTrue(controller.transport_close_triggered)

        message = controller.message_received_message

        self.assertIsNotNone(message)

        self.assertEqual(message.http_version, 10)

        self.assertEqual(message.status_code, 200)

        self.assertEqual(message.headers.get_first("Connection"), "Close")
        self.assertEqual(message.headers.get_first("Content-Length"), "13")

        self.assertEqual(message.body, b"Hello, World!")
