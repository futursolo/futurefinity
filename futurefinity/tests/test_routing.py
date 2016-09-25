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

from futurefinity.routing import RoutingRule, RoutingLocator

import re


class RoutingTestCase(TestCase):
    def test_routing_rule(self):
        handler = object()

        rule = RoutingRule(
            handler=handler, path_args=["a"], path_kwargs={"b": "c"})

        assert rule.handler is handler
        assert rule.path_args == ["a"]
        assert rule.path_kwargs == {"b": "c"}

    def test_locator_add(self):
        handler = object()
        locator = RoutingLocator()

        locator.add(r"/", handler, "a", "b", "c", name="root", d="e")

        assert "root" in locator.links_dict
        assert locator.links_dict["root"] in locator.handlers_dict

        assert locator.links_dict["root"] == re.compile(r"/")

        rule = locator.handlers_dict[locator.links_dict["root"]]

        assert rule.handler is handler
        assert rule.path_args == ["a", "b", "c"]
        assert rule.path_kwargs == {"d": "e"}

    def test_locator_find(self):
        handler = object()
        locator = RoutingLocator()

        locator.add(r"/(.*?)/(?P<d>.*?)/(?P<f>.*?)",
                    handler, "a", "b", "c", d="e")

        rule = locator.find("/asdf/ghjk/qwerty")

        assert rule.handler is handler
        assert rule.path_args == ["a", "b", "c", "asdf", "ghjk", "qwerty"]
        assert rule.path_kwargs == {"d": "e", "f": "qwerty"}

    def test_locator_find_default(self):
        handler = object()
        locator = RoutingLocator(default_handler=handler)

        locator.add(path=r"/a", handler=object())

        rule = locator.find("/b")

        assert rule.handler is handler
        assert rule.path_args == []
        assert rule.path_kwargs == {}
