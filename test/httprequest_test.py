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
import unittest
import functools


class HTTPRequestTestCollector(unittest.TestCase):

    def test_httprequest_parse_get(self):
        request = futurefinity.protocol.HTTPRequest()
        self.assertFalse(request.parse_http_v1_request(b"GET / HTTP/1.1\r\n"))
        self.assertFalse(request.parse_http_v1_request(b"Host: localhost\r\n"))
        self.assertFalse(request.parse_http_v1_request(b"Custom: CHeader\r\n"))
        self.assertFalse(request.parse_http_v1_request(b"Custom: CHeader\r\n"))
        self.assertFalse(request.parse_http_v1_request(
            b"Cookie: a=b;c=d;e=f;\r\n"))
        self.assertTrue(request.parse_http_v1_request(b"\r\n"))

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
        self.assertFalse(request.parse_http_v1_request(b"GET /data HTTP/1.1"))
        self.assertTrue(request.parse_http_v1_request(b"\r\n\r\n"))

        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/data")
        self.assertEqual(request.http_version, 11)

    def test_httprequest_parse_post_encoded(self):
        request = futurefinity.protocol.HTTPRequest()
        body = b"a=b&c=d&anyway=itisok"
        self.assertFalse(request.parse_http_v1_request(b"POST / HTTP/1.1\r\n"))
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Type: application/x-www-form-urlencoded\r\n"))
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Length: %d\r\n" % len(body)))
        self.assertFalse(request.parse_http_v1_request(b"\r\n"))
        self.assertTrue(request.parse_http_v1_request(body))

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

        self.assertFalse(request.parse_http_v1_request(b"POST / HTTP/1.1\r\n"))
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Type: multipart/form-data; boundary=-----as7B98bFk\r\n"))
        self.assertFalse(request.parse_http_v1_request(
            b"Content-Length: %d\r\n" % len(body)))
        self.assertFalse(request.parse_http_v1_request(b"\r\n"))
        self.assertTrue(request.parse_http_v1_request(body))
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
