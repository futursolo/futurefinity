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

from futurefinity.tests.utils import TestCase
from futurefinity.security import get_random_str

from futurefinity.utils import (
    ensure_bytes, ensure_str, format_timestamp)

import os
import time
import pytest
import random
import calendar
import datetime
import email.utils


class EnsureBytesTestCase(TestCase):
    def test_ensure_bytes_from_bytes(self):
        random_bytes = os.urandom(10)
        ensured_bytes = ensure_bytes(random_bytes)

        assert random_bytes == ensured_bytes

    def test_ensure_bytes_from_bytearray(self):
        random_bytearray = bytearray(os.urandom(10))
        ensured_bytes = ensure_bytes(random_bytearray)

        assert bytes(random_bytearray) == ensured_bytes

    def test_ensure_bytes_from_none(self):
        assert b"" == ensure_bytes(None)

    def test_ensure_bytes_from_other(self):
        assert isinstance(ensure_bytes(object()), bytes)

    def test_ensure_bytes_from_str(self):
        random_str = get_random_str(10)

        assert random_str.encode() == ensure_bytes(random_str)


class EnsureStrTestCase(TestCase):
    def test_ensure_str_from_str(self):
        random_str = get_random_str(10)
        ensured_str = ensure_str(random_str)

        assert random_str == ensured_str

    def test_ensure_str_from_bytearray(self):
        random_str = get_random_str(10)
        encoded_bytearray = bytearray(random_str.encode())

        assert random_str == ensure_str(encoded_bytearray)

    def test_ensure_str_from_none(self):
        assert "" == ensure_str(None)

    def test_ensure_str_from_other(self):
        assert isinstance(ensure_str(object()), str)

    def test_ensure_str_from_bytes(self):
        random_str = get_random_str(10)
        encoded_bytes = random_str.encode()

        assert random_str == ensure_str(encoded_bytes)


class FormatTimestampTestCase(TestCase):
    def test_format_timestamp_with_real_number(self):
        timestamp = time.time()
        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == format_timestamp(timestamp)

    def test_format_timestamp_with_none(self):
        timestamp = time.time()
        timestamp_future = timestamp + 1

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)
        formatted_timestamp_future = email.utils.formatdate(timestamp,
                                                            usegmt=True)
        assert format_timestamp() in [
            formatted_timestamp, formatted_timestamp_future]

    def test_format_timestamp_with_struct_time(self):
        struct_time = time.gmtime()
        timestamp = calendar.timegm(struct_time)

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == format_timestamp(struct_time)

    def test_format_timestamp_with_tuple(self):
        time_tuple = tuple(time.gmtime())
        timestamp = calendar.timegm(time_tuple)

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == format_timestamp(time_tuple)

    def test_format_timestamp_with_datetime(self):
        datetime_time = datetime.datetime.utcnow()
        timestamp = calendar.timegm(datetime_time.utctimetuple())

        formatted_timestamp = email.utils.formatdate(timestamp, usegmt=True)

        assert formatted_timestamp == format_timestamp(datetime_time)

    def test_format_timestamp_with_other(self):
        with pytest.raises(TypeError):
            format_timestamp(object())
