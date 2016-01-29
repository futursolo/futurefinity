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

from futurefinity.utils import *

import futurefinity.protocol

import os
import nose2
import base64
import unittest
import functools
import email.parser


class HTTPRequestTestCollector(unittest.TestCase):

    def test_httprequest_parse_get(self):
        request = futurefinity.protocol.HTTPRequest()
        self.assertFalse(request.parse_http_v1_request(
            b"GET / HTTP/1.1\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Host: localhost\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Custom: CHeader\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Custom: CHeader\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Cookie: a=b;c=d;e=f;\r\n")
                [0])
        self.assertTrue(request.parse_http_v1_request(b"\r\n")[0])

        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/")
        self.assertEqual(request.http_version, 11)
        self.assertEqual(request.host, "localhost")
        self.assertEqual(request.headers.get_first("custom"), "CHeader")

        self.assertEqual(request.cookies["a"].value, "b")
        self.assertEqual(request.cookies["c"].value, "d")
        self.assertEqual(request.cookies["e"].value, "f")

    def test_httprequest_parse_get_noheader(self):
        request = futurefinity.protocol.HTTPRequest()
        self.assertFalse(request.parse_http_v1_request(
            b"GET /data HTTP/1.1")[0])
        self.assertTrue(request.parse_http_v1_request(b"\r\n\r\n")[0])

        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/data")
        self.assertEqual(request.http_version, 11)

    def test_httprequest_parse_post_encoded(self):
        request = futurefinity.protocol.HTTPRequest()
        body = b"a=b&c=d&anyway=itisok"
        self.assertFalse(request.parse_http_v1_request(
            b"POST / HTTP/1.1\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Type: application/x-www-form-urlencoded\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Length: %d\r\n" % len(body))[0])
        self.assertTrue(request.parse_http_v1_request(b"\r\n")[0])

        self.assertTrue(request.body.parse_http_v1_body(body))

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/")
        self.assertEqual(request.http_version, 11)
        self.assertEqual(request.headers.get_first("content-type"),
                         "application/x-www-form-urlencoded")
        self.assertEqual(request.headers.get_first("content-length"),
                         str(len(body)))

        self.assertEqual(request.body.get_first("a"), "b")
        self.assertEqual(request.body.get_first("c"), "d")
        self.assertEqual(request.body.get_first("anyway"), "itisok")

    def test_httprequest_parse_post_multipart(self):
        request = futurefinity.protocol.HTTPRequest()
        file_content = os.urandom(32)
        body = b"-------as7B98bFk\r\n"
        body += b"Content-Disposition: form-data; name=\"normal-field\"\r\n"
        body += b"\r\n"
        body += b"hello\r\n"
        body += b"-------as7B98bFk\r\n"
        body += b"Content-Disposition: form-data; name=\"file-field\"; \
filename=\"test.txt\"\r\n"
        body += b"Content-Type: application/octet-stream\r\n"
        body += b"Content-Transfer-Encoding: binary\r\n"
        body += b"\r\n"
        body += file_content + b"\r\n"
        body += b"-------as7B98bFk--\r\n"

        self.assertFalse(
            request.parse_http_v1_request(b"POST / HTTP/1.1\r\n")[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Type: multipart/form-data; boundary=-----as7B98bFk\r\n"
        )[0])
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Length: %d\r\n" % len(body))[0])
        self.assertTrue(request.parse_http_v1_request(b"\r\n")[0])
        self.assertTrue(request.body.parse_http_v1_body(body))
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/")
        self.assertEqual(request.http_version, 11)
        self.assertEqual(request.headers.get_first("content-type"),
                         "multipart/form-data; boundary=-----as7B98bFk")
        self.assertEqual(request.headers.get_first("content-length"),
                         str(len(body)))

        self.assertEqual(request.body.get_first("normal-field"), "hello")

        self.assertTrue(isinstance(request.body.get_first("file-field"),
                        futurefinity.protocol.HTTPFile))
        self.assertEqual(request.body.get_first("file-field").content,
                         file_content)
        self.assertEqual(request.body.get_first("file-field").filename,
                         "test.txt")
        self.assertEqual(request.body.get_first("file-field").encoding,
                         "binary")

    def test_httprequest_make_get_request(self):
        request = futurefinity.protocol.HTTPRequest()
        request.method = "GET"
        request.path = "/"
        request.headers.add("Custom", "CHeader")
        request.queries.add("asdf", "fdsa")
        request.cookies["custom"] = "cookie-value"

        request_bytes = request.make_http_v1_request()

        request_initial, request_rest = request_bytes.split(b"\r\n", 1)

        self.assertEqual(request_initial, b"GET /?asdf=fdsa HTTP/1.1")

        message = email.parser.BytesParser().parsebytes(request_rest)

        self.assertEqual(message["Custom"], "CHeader")
        self.assertEqual(message["Cookie"], "custom=cookie-value; ")
        self.assertFalse(message.is_multipart())

    def test_httprequest_make_post_request(self):
        request = futurefinity.protocol.HTTPRequest()
        request.method = "POST"
        request.path = "/"

        request.body.set_content_type("application/x-www-form-urlencoded")
        request.body.add("bodyfield", "hello")

        request_bytes = request.make_http_v1_request()

        request_initial, request_rest = request_bytes.split(b"\r\n", 1)

        request_header, request_body = request_rest.split(b"\r\n\r\n", 1)

        self.assertEqual(request_initial, b"POST / HTTP/1.1")

        request_header += b"\r\n"
        message = email.parser.BytesParser().parsebytes(request_header)

        self.assertFalse(message.is_multipart())
        self.assertEqual(message["Content-Type"],
                         "application/x-www-form-urlencoded")

        self.assertEqual(request_body, b"bodyfield=hello")



    def test_httprequest_make_get_request(self):
        request = futurefinity.protocol.HTTPRequest()
        request.method = "GET"
        request.path = "/"
        request.headers.add("Custom", "CHeader")
        request.queries.add("asdf", "fdsa")
        request.cookies["custom"] = "cookie-value"

        request_bytes = request.make_http_v1_request()

        request_initial, request_rest = request_bytes.split(b"\r\n", 1)

        self.assertEqual(request_initial, b"GET /?asdf=fdsa HTTP/1.1")

        message = email.parser.BytesParser().parsebytes(request_rest)

        self.assertEqual(message["Custom"], "CHeader")
        self.assertEqual(message["Cookie"], "custom=cookie-value; ")
        self.assertFalse(message.is_multipart())

    def test_httprequest_make_post_urlencoded_request(self):
        request = futurefinity.protocol.HTTPRequest()
        request.method = "POST"
        request.path = "/"

        request.body.set_content_type("application/x-www-form-urlencoded")
        request.body.add("bodyfield", "hello")

        request_bytes = request.make_http_v1_request()

        request_initial, request_rest = request_bytes.split(b"\r\n", 1)

        self.assertEqual(request_initial, b"POST / HTTP/1.1")

        message = email.parser.BytesParser().parsebytes(request_rest)

        self.assertFalse(message.is_multipart())
        self.assertEqual(message["Content-Type"],
                         "application/x-www-form-urlencoded")

        self.assertEqual(message.get_payload(), "bodyfield=hello")

    def test_httprequest_make_post_multipart_request(self):
        request = futurefinity.protocol.HTTPRequest()
        request.method = "POST"
        request.path = "/"

        file_content = ensure_bytes(base64.b64encode(os.urandom(32)))

        body_file = futurefinity.protocol.HTTPFile(fieldname="filefield",
                                                   filename="test.txt",
                                                   content=file_content)

        request.body.set_content_type("multipart/form-data")
        request.body.add("textfield", "hello")
        request.body.add("filefield", body_file)

        request_bytes = request.make_http_v1_request()

        request_initial, request_rest = request_bytes.split(b"\r\n", 1)

        self.assertEqual(request_initial, b"POST / HTTP/1.1")

        message = email.parser.BytesParser().parsebytes(request_rest)

        self.assertTrue(message.is_multipart())
        self.assertTrue(
            message["Content-Type"].startswith("multipart/form-data"))

        body_payload = message.get_payload()
        for field in body_payload:
            if field.get_filename() is None:
                self.assertEqual(ensure_str(field.get_payload()), "hello")
            else:
                self.assertEqual(field.get_filename(), "test.txt")

                self.assertEqual(ensure_bytes(field.get_payload()),
                                 file_content)
