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

from futurefinity.utils import ensure_bytes

import futurefinity
import futurefinity.protocol

import os
import nose2
import unittest


class HTTPResponseTestCollector(unittest.TestCase):
    def test_httpresponse_parse_response(self):
        body = os.urandom(32)
        server = "FutureFinity/%s" % futurefinity.version
        response = futurefinity.protocol.HTTPResponse()

        self.assertFalse(
            response.parse_http_v1_response(b"HTTP/1.1 200 OK\r\n")[0])
        self.assertFalse(
            response.parse_http_v1_response(
                b"Content-Length: %d\r\n" % len(body))[0])
        self.assertFalse(
            response.parse_http_v1_response(
                ensure_bytes("Server: %s\r\n" % server))[0])

        self.assertFalse(response.parse_http_v1_response(
            b"Set-Cookie: a=b; httponly; secure; max-age=10000\r\n")[0])

        self.assertFalse(response.parse_http_v1_response(
            b"Set-Cookie: c=d; httponly; secure; expires=\
\"Thu, 01 Jan 1970 00:00:00 GMT\";\r\n")[0])
        self.assertTrue(response.parse_http_v1_response(b"\r\n")[0])

        response.body += body

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.http_version, 11)
        self.assertEqual(response.headers.get_first("server"), server)

        self.assertEqual(response.cookies["a"].value, "b")
        self.assertTrue(response.cookies["a"]["httponly"])
        self.assertTrue(response.cookies["a"]["secure"])
        self.assertEqual(response.cookies["a"]["max-age"], 10000)

        self.assertEqual(response.cookies["c"].value, "d")
        self.assertTrue(response.cookies["c"]["httponly"])
        self.assertTrue(response.cookies["c"]["secure"])
        self.assertEqual(response.cookies["c"]["expires"],
                         '"Thu, 01 Jan 1970 00:00:00 GMT"')

        self.assertEqual(response.body, body)
