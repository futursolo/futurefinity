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

from futurefinity.routing import Dispatcher, NoMatchesFound
from futurefinity.web import RequestHandler

import re
import pytest


class RoutingTestCase(TestCase):
    def test_dispatcher_add(self):
        dispatcher = Dispatcher()

        dispatcher.add(
            r"/", "a", "b", "c", Handler=RequestHandler, name="root", d="e")

        assert "root" in dispatcher._name_dict.keys()

        rule = dispatcher._name_dict["root"]

        assert "root" in dispatcher._name_dict.keys()
        assert rule.path == re.compile(r"/")

        assert rule.Handler is RequestHandler
        assert rule.path_args == ["a", "b", "c"]
        assert rule.path_kwargs == {"d": "e"}

    def test_dispatcher_find(self):
        dispatcher = Dispatcher()

        dispatcher.add(r"/(.*?)/(?P<d>.*?)/(?P<f>.*?)", "a", "b", "c",
                    Handler=RequestHandler, d="e")

        Handler, args, kwargs = dispatcher.find("/asdf/ghjk/qwerty")

        assert Handler is RequestHandler
        assert args == ["a", "b", "c", "asdf", "ghjk", "qwerty"]
        assert kwargs == {"d": "e", "f": "qwerty"}

    def test_dispatcher_find_default(self):
        dispatcher = Dispatcher(DefaultHandler=RequestHandler)

        class SubHandler(RequestHandler):
            pass

        dispatcher.add(path=r"/a", Handler=SubHandler)

        Handler, args, kwargs = dispatcher.find("/b")

        assert Handler is RequestHandler
        assert args == []
        assert kwargs == {}

    def test_dispatcher_find_no_default_raised(self):
        dispatcher = Dispatcher()

        class SubHandler(RequestHandler):
            pass

        dispatcher.add(path=r"/a", Handler=SubHandler)

        with pytest.raises(NoMatchesFound):
            dispatcher.find("/b")

    def test_dispatcher_reverse_positional(self):
        dispatcher = Dispatcher()

        dispatcher.add(r"/(.*?)/(?P<d>.*?)/(?P<f>.*?)",
                    Handler=RequestHandler, name="test")

        assert "/asdf/ghjk/qwerty" == dispatcher.reverse(
            name="test", path_args=["asdf", "ghjk", "qwerty"])

    def test_dispatcher_reverse_positional(self):
        dispatcher = Dispatcher()

        dispatcher.add(r"/(?P<a>.*?)/(?P<b>.*?)/(?P<c>.*?)",
                    Handler=RequestHandler, name="test")

        assert "/asdf/ghjk/qwerty" == dispatcher.reverse(
            name="test", path_kwargs={"a": "asdf", "b": "ghjk", "c": "qwerty"})
