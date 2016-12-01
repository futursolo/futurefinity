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

from futurefinity.magicdict import MagicDict, TolerantMagicDict

import random


class MagicDictTestCase(TestCase):
    def test_init_magic_dict(self):
        test_data = {"a": "b", "c": b"d", "e": random.choice(range(0, 100))}

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
