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

import futurefinity

import pytest
import random


class MagicItemsViewTestCase:
    def test_len_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        dict_len = random.choice(range(10, 90))
        for i in range(0, dict_len):
            magic_dict.add(
                futurefinity.security.get_random_str(5),
                futurefinity.security.get_random_str(5))

        assert len(magic_dict.items()) == dict_len

    def test_iter_method_magic_items_view(self):
        items_list = []
        for i in range(0, random.choice(range(10, 90))):
            items_list.append(
                (futurefinity.security.get_random_str(5),
                 futurefinity.security.get_random_str(5)))

        magic_dict = futurefinity.magicdict.MagicDict(items_list)

        assert list(magic_dict.items()) == items_list

    def test_contains_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        assert ("a", "b") in magic_dict.items()
        assert ("a", "c") in magic_dict.items()

    def test_le_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.items() <= magic_dict2.items()

    def test_lt_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.items() < magic_dict2.items()

    def test_eq_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.items() == magic_dict2.items()

    def test_ne_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "d")

        assert magic_dict.items() != magic_dict2.items()

    def test_gt_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert magic_dict.items() > magic_dict2.items()

    def test_ge_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.items() >= magic_dict2.items()

    def test_and_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert (magic_dict.items() & magic_dict2.items()) == set([("a", "b")])

    def test_or_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert (magic_dict.items() | magic_dict2.items()) == set(
            [("a", "b"), ("a", "c")])

    def test_sub_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert (magic_dict.items() - magic_dict2.items()) == set([("a", "c")])

    def test_xor_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert (magic_dict.items() ^ magic_dict2.items()) == set([("a", "c")])

    def test_reversed_method_magic_items_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "c")
        magic_dict2.add("a", "b")

        assert reversed(magic_dict.items()) == magic_dict2.items()


class MagicKeysViewTestCase:
    def test_len_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        dict_len = random.choice(range(10, 90))
        for i in range(0, dict_len):
            magic_dict.add(
                futurefinity.security.get_random_str(5),
                futurefinity.security.get_random_str(5))

        assert len(magic_dict.keys()) == dict_len

    def test_iter_method_magic_keys_view(self):
        items_list = []
        for i in range(0, random.choice(range(10, 90))):
            items_list.append(
                (futurefinity.security.get_random_str(5),
                 futurefinity.security.get_random_str(5)))

        magic_dict = futurefinity.magicdict.MagicDict(items_list)

        assert list(magic_dict.keys()) == [i for i, _ in items_list]

    def test_contains_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        assert "a" in magic_dict.keys()

    def test_le_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.keys() <= magic_dict2.keys()

    def test_lt_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("c", "d")

        assert magic_dict.keys() < magic_dict2.keys()

    def test_eq_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.keys() == magic_dict2.keys()

    def test_ne_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("c", "d")

        assert magic_dict.keys() != magic_dict2.keys()

    def test_gt_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("c", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert magic_dict.keys() > magic_dict2.keys()

    def test_ge_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.keys() >= magic_dict2.keys()

    def test_and_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("c", "d")

        assert (magic_dict.keys() & magic_dict2.keys()) == set(["a"])

    def test_or_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "c")
        magic_dict.add("b", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("c", "d")

        assert (magic_dict.keys() | magic_dict2.keys()) == set(
            ["a", "b", "c"])

    def test_sub_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("c", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("c", "d")

        assert (magic_dict.keys() - magic_dict2.keys()) == set(["a"])

    def test_xor_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("c", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")

        assert (magic_dict.keys() ^ magic_dict2.keys()) == set(["c"])

    def test_reversed_method_magic_keys_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("c", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("c", "d")
        magic_dict2.add("a", "b")

        assert reversed(magic_dict.keys()) == magic_dict2.keys()


class MagicValuesViewTestCase:
    def test_len_method_magic_values_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        dict_len = random.choice(range(10, 90))
        for i in range(0, dict_len):
            magic_dict.add(
                futurefinity.security.get_random_str(5),
                futurefinity.security.get_random_str(5))

        assert len(magic_dict.values()) == dict_len

    def test_iter_method_magic_values_view(self):
        items_list = []
        for i in range(0, random.choice(range(10, 90))):
            items_list.append(
                (futurefinity.security.get_random_str(5),
                 futurefinity.security.get_random_str(5)))

        magic_dict = futurefinity.magicdict.MagicDict(items_list)

        assert list(magic_dict.values()) == [i for _, i in items_list]

    def test_contains_method_magic_values_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        assert "b" in magic_dict.values()
        assert "c" in magic_dict.values()

    def test_eq_method_magic_values_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("a", "c")

        assert magic_dict.values() == magic_dict2.values()

    def test_ne_method_magic_values_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("a", "c")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("a", "b")
        magic_dict2.add("c", "d")

        assert magic_dict.values() != magic_dict2.values()

    def test_reversed_method_magic_values_view(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict.add("a", "b")
        magic_dict.add("c", "d")

        magic_dict2 = futurefinity.magicdict.MagicDict()

        magic_dict2.add("c", "d")
        magic_dict2.add("a", "b")

        assert reversed(magic_dict.values()) == magic_dict2.values()


class MagicDictTestCase:
    def test_init_method_magic_dict(self):
        test_data = {"a": "b", "c": b"d", "e": random.choice(range(0, 100))}

        assert futurefinity.magicdict.MagicDict(test_data) == test_data
        assert futurefinity.magicdict.MagicDict(**test_data) == test_data

    def test_getitem_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        assert magic_dict["a"] == "b"

    def test_setitem_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict["a"] = "b"

        assert magic_dict.get_list("a") == ["b"]

    def test_delitem_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        del magic_dict["a"]
        assert "a" not in magic_dict

    def test_iter_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")
        magic_dict.add("b", "e")

        result_set = set()
        for key in iter(magic_dict):
            result_set.add(key)

        assert result_set == set(["a", "b"])

    def test_len_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")
        magic_dict.add("b", "e")

        assert len(magic_dict) == 3

    def test_contains_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict["a"] = "b"

        assert ("a" in magic_dict) is True
        assert ("c" in magic_dict) is False

    def test_eq_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict["a"] = "b"

        assert magic_dict == {"a": "b"}
        assert (magic_dict == {"c": "d"}) is False

    def test_ne_method_magic_dict(self):

        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict["a"] = "b"

        assert magic_dict != {"c": "d"}
        assert (magic_dict != {"a": "b"}) is False

    def test_str_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "b")

        assert str(magic_dict) == "MagicDict([('a', 'b')])"

    def test_reversed_method_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict["a"] = "b"
        magic_dict["c"] = "d"
        magic_dict["e"] = "f"

        assert magic_dict == futurefinity.magicdict.MagicDict(
            [("a", "b"), ("c", "d"), ("e", "f")])
        assert reversed(magic_dict) == futurefinity.magicdict.MagicDict(
            [("e", "f"), ("c", "d"), ("a", "b")])

    def test_add_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        assert "a" not in magic_dict

        magic_dict.add("a", "b")

        assert "a" in magic_dict
        assert magic_dict["a"] == "b"

    def test_pop_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        magic_dict["a"] = "b"

        assert magic_dict.pop("a") == "b"
        assert len(magic_dict) == 0

    def test_popitem_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        magic_dict["a"] = "b"

        assert magic_dict.popitem() == ("a", "b")
        assert len(magic_dict) == 0

    def test_clear_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        magic_dict["a"] = "b"
        magic_dict.clear()

        assert len(magic_dict) == 0

    def test_setdefault_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict["a"] = "b"
        magic_dict.setdefault("a", "c")
        magic_dict.setdefault("d", "e")

        assert magic_dict["a"] == "b"
        assert magic_dict["d"] == "e"

    def test_fromkeys_magic_dict(self):
        keys = ["a", "b", "c"]
        magic_dict = futurefinity.magicdict.MagicDict.fromkeys(keys, value="d")

        assert magic_dict["a"] == "d"
        assert magic_dict["b"] == "d"
        assert magic_dict["c"] == "d"

    def test_get_first_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add("a", item)

        assert magic_dict.get_first("a") == test_list[0]

    def test_get_last_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add("a", item)

        assert magic_dict.get_last("a") == test_list[-1]

    def test_get_list_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add("a", item)

        assert magic_dict.get_list("a") == test_list

    def test_items_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

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

    def test_keys_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        test_set = set(["d", "e", "f"])
        for item in test_set:
            magic_dict.add("a", item)
            magic_dict.add("b", item)
            magic_dict.add("c", item)

        result_set = set()
        for key in magic_dict.keys():
            result_set.add(key)

        assert result_set == set(["a", "b", "c"])

    def test_values_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

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

    def test_freeze_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict["a"] = "b"

        magic_dict.freeze()

        with pytest.raises(futurefinity.magicdict.MagicDictFrozenError):
            magic_dict["c"] = "d"

        assert magic_dict["a"] == "b"

    def test_frozen_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()

        magic_dict["a"] = "b"

        magic_dict.freeze()

        assert magic_dict.frozen()

        assert magic_dict["a"] == "b"

    def test_copy_magic_dict(self):
        magic_dict = futurefinity.magicdict.MagicDict()
        magic_dict.add("a", "b")

        copied_magic_dict = magic_dict.copy()

        assert magic_dict == copied_magic_dict


class TolerantMagicDictTestCase:
    def test_getitem_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("a", "c")
        magic_dict.add("a", "d")

        assert magic_dict["A"] == "b"

    def test_setitem_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict["A"] = "b"

        assert magic_dict.get_list("a") == ["b"]

    def test_delitem_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("A", "c")
        magic_dict.add("a", "d")

        del magic_dict["a"]
        assert "a" not in magic_dict
        assert "A" not in magic_dict

    def test_contains_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict["a"] = "b"

        assert ("A" in magic_dict) is True
        assert ("c" in magic_dict) is False

    def test_str_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict.add("A", "b")

        assert str(magic_dict) == "TolerantMagicDict([('a', 'b')])"

    def test_reversed_method_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict["A"] = "b"
        magic_dict["c"] = "d"
        magic_dict["E"] = "f"

        assert magic_dict == futurefinity.magicdict.TolerantMagicDict(
            [("a", "b"), ("c", "d"), ("e", "f")])
        assert reversed(
            magic_dict) == futurefinity.magicdict.TolerantMagicDict(
                [("e", "f"), ("c", "d"), ("a", "b")])

    def test_add_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        assert "a" not in magic_dict

        magic_dict.add("A", "b")

        assert "a" in magic_dict
        assert "A" in magic_dict

        assert magic_dict["a"] == "b"

    def test_pop_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        magic_dict["A"] = "b"

        assert magic_dict.pop("a") == "b"
        assert len(magic_dict) == 0

    def test_setdefault_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        magic_dict["a"] = "b"
        magic_dict.setdefault("A", "c")
        magic_dict.setdefault("D", "e")

        assert magic_dict["a"] == "b"
        assert magic_dict["d"] == "e"

    def test_fromkeys_tolerant_magic_dict(self):
        keys = ["A", "b", "C"]
        magic_dict = futurefinity.magicdict.TolerantMagicDict.fromkeys(
            keys, value="d")

        assert magic_dict["a"] == "d"
        assert magic_dict["b"] == "d"
        assert magic_dict["c"] == "d"

    def test_get_first_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add(random.choice(["a", "A"]), item)

        assert magic_dict.get_first(random.choice(["a", "A"])) == test_list[0]

    def test_get_last_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add(random.choice(["a", "A"]), item)

        assert magic_dict.get_last(random.choice(["a", "A"])) == test_list[-1]

    def test_get_iter_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()

        test_list = ["b", "c", "d"]
        for item in test_list:
            magic_dict.add(random.choice(["a", "A"]), item)

        assert magic_dict.get_list(random.choice(["a", "A"])) == test_list

    def test_copy_tolerant_magic_dict(self):
        magic_dict = futurefinity.magicdict.TolerantMagicDict()
        magic_dict.add("a", "b")
        magic_dict.add("C", "D")

        copied_magic_dict = magic_dict.copy()

        assert magic_dict == copied_magic_dict
