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
import futurefinity.httputils

import time
import pytest
import calendar
import datetime
import magicdict
import email.utils
import http.cookies


class ParseHeadersTestCase:
    def test_parse_headers_with_str(self):
        test_string = "Header-A: value-a\r\nHeader-B: value-b\r\n"

        headers = futurefinity.httputils.parse_headers(test_string)

        assert list(headers.keys()) == list(["header-a", "header-b"])
        assert headers["header-a"] == "value-a"
        assert headers["header-b"] == "value-b"

    def test_parse_headers_with_bytes(self):
        test_string = \
            b"Header-A: value-a\r\nHeader-B: value-b\r\nHeader-A: value-c\r\n"

        headers = futurefinity.httputils.parse_headers(test_string)

        assert set(headers.keys()) == set(["header-a", "header-b"])
        assert headers.get_list("header-a") == ["value-a", "value-c"]
        assert headers["header-b"] == "value-b"


class BuildHeadersTestCase:
    def test_http_build_headers(self):
        headers = magicdict.TolerantMagicDict()

        headers["header-a"] = "value-a"
        headers["header-b"] = "value-b"

        assert futurefinity.httputils.build_headers(headers) in [
            b"Header-A: value-a\r\nHeader-B: value-b\r\n",
            b"Header-B: value-b\r\nHeader-A: value-a\r\n"]


class FormatTimestampTestCase:
    def test_format_timestamp_with_real_number(self):
        timestamp = time.time()
        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == futurefinity.httputils.format_timestamp(
            timestamp)

    def test_format_timestamp_with_none(self):
        timestamp = time.time()
        timestamp_future = timestamp + 1

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)
        formatted_timestamp_future = email.utils.formatdate(timestamp,
                                                            usegmt=True)
        assert futurefinity.httputils.format_timestamp() in [
            formatted_timestamp, formatted_timestamp_future]

    def test_format_timestamp_with_struct_time(self):
        struct_time = time.gmtime()
        timestamp = calendar.timegm(struct_time)

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == futurefinity.httputils.format_timestamp(
            struct_time)

    def test_format_timestamp_with_tuple(self):
        time_tuple = tuple(time.gmtime())
        timestamp = calendar.timegm(time_tuple)

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == futurefinity.httputils.format_timestamp(
            time_tuple)

    def test_format_timestamp_with_datetime(self):
        datetime_time = datetime.datetime.utcnow()
        timestamp = calendar.timegm(datetime_time.utctimetuple())

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == futurefinity.httputils.format_timestamp(
            datetime_time)

    def test_format_timestamp_with_other(self):
        with pytest.raises(TypeError):
            futurefinity.httputils.format_timestamp(object())


class BuildCookiesTestCase:
    def test_http_headers_build_cookies_for_request(self):
        cookies = http.cookies.SimpleCookie()

        cookies["cookie-b"] = "value-b"

        headers = futurefinity.httputils.build_cookies_for_request(cookies)

        assert headers["cookie"] == "cookie-b=value-b; "

    def test_http_headers_build_cookies_for_response(self):
        cookies = http.cookies.SimpleCookie()

        cookies["cookie-a"] = "value-a"

        headers = futurefinity.httputils.build_cookies_for_response(cookies)

        assert headers["set-cookie"] == "cookie-a=value-a"
