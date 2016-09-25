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
    ensure_bytes, ensure_str, format_timestamp, MagicDict, TolerantMagicDict)

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


class MagicDictTestCase(TestCase):
    def test_init_magic_dict(self):
        test_data = {"a": "b", "c": b"d", "e": random.random()}

        assert MagicDict(test_data) == test_data
        assert MagicDict(**test_data) == test_data

    def test_magic_dict_add(self):
        magic_dict = MagicDict()

        assert "a" not in magic_dict

        magic_dict.add("a", "b")

        assert "a" in magic_dict
        assert magic_dict["a"] == "b"

    def test_magic_dict_get_list(self):
        magic_dict = MagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add("a", item)

        assert magic_dict.get_list("a") == test_list

    def test_magic_dict_get_first(self):
        magic_dict = MagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add("a", item)

        assert magic_dict.get_first("a") == test_list[0]

    def test_magic_dict_items(self):
        magic_dict = MagicDict()

        test_set = set(["d", "e", "f"])
        for item in test_set:
            magic_dict.add("a", item)
            magic_dict.add("b", item)
            magic_dict.add("c", item)

        result_dict = {"a": set(), "b": set(), "c": set()}
        for key, value in magic_dict.items():
            result_dict[key].add(value)

        assert result_dict["a"] == test_set
        assert result_dict["b"] == test_set
        assert result_dict["c"] == test_set

    def test_magic_dict_keys(self):
        magic_dict = MagicDict()

        test_set = set(["d", "e", "f"])
        for item in test_set:
            magic_dict.add("a", item)
            magic_dict.add("b", item)
            magic_dict.add("c", item)

        result_set = set()
        for key in magic_dict.keys():
            result_set.add(key)

        assert result_set == set(["a", "b", "c"])

    def test_magic_dict_values(self):
        magic_dict = MagicDict()

        test_set = set(["d", "e", "f"])
        for item in test_set:
            magic_dict.add("a", item)
            magic_dict.add("b", item)
            magic_dict.add("c", item)

        result_dict = {"d": 0, "e": 0, "f": 0}
        for value in magic_dict.values():
            result_dict[value] += 1

        assert result_dict["d"] == 3
        assert result_dict["e"] == 3
        assert result_dict["f"] == 3

    def test_magic_dict_setitem_method(self):
        magic_dict = MagicDict()
        magic_dict["a"] = "b"

        assert magic_dict.get_list("a") == ["b"]

    def test_magic_dict_getitem_method(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        assert magic_dict["a"] == "b"

    def test_magic_dict_delitem_method(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        del magic_dict["a"]
        assert "a" not in magic_dict

    def test_magic_dict_len_method(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")
        magic_dict.add("b", "e")

        assert len(magic_dict) == 3

    def test_magic_dict_iter_method(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")
        magic_dict.add("b", "e")

        result_set = set()
        for key in iter(magic_dict):
            result_set.add(key)

        assert result_set == set(["a", "b"])

    def test_magic_dict_str_method(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "b")

        assert str(magic_dict) == "MagicDict([('a', 'b')])"

    def test_magic_dict_copy(self):
        magic_dict = MagicDict()
        magic_dict.add("a", "b")

        copied_magic_dict = magic_dict.copy()

        assert magic_dict == copied_magic_dict


class TolerantMagicDictTestCase(TestCase):
    def test_tolerant_magic_dict_add(self):
        magic_dict = TolerantMagicDict()

        assert "a" not in magic_dict

        magic_dict.add("A", "b")

        assert "a" in magic_dict
        assert "A" in magic_dict

        assert magic_dict["a"] == "b"

    def test_tolerant_magic_dict_get_list(self):
        magic_dict = TolerantMagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add(random.choice(["a", "A"]), item)

        assert magic_dict.get_list(random.choice(["a", "A"])) == test_list

    def test_tolerant_magic_dict_get_first(self):
        magic_dict = TolerantMagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add(random.choice(["a", "A"]), item)

        assert magic_dict.get_first(random.choice(["a", "A"])) == test_list[0]

    def test_tolerant_magic_dict_setitem_method(self):
        magic_dict = TolerantMagicDict()
        magic_dict["A"] = "b"

        assert magic_dict.get_list("a") == ["b"]

    def test_tolerant_magic_dict_getitem_method(self):
        magic_dict = TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        assert magic_dict["A"] == "b"

    def test_tolerant_magic_dict_delitem_method(self):
        magic_dict = TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("A", "c")
        magic_dict.add("a", "d")

        del magic_dict["a"]
        assert "a" not in magic_dict
        assert "A" not in magic_dict

    def test_tolerant_magic_dict_str_method(self):
        magic_dict = TolerantMagicDict()
        magic_dict.add("A", "b")

        assert str(magic_dict) == "TolerantMagicDict([('a', 'b')])"

    def test_tolerant_magic_dict_copy(self):
        magic_dict = TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("C", "D")

        copied_magic_dict = magic_dict.copy()

        assert magic_dict == copied_magic_dict
