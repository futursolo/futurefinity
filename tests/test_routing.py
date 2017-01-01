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

import re
import pytest


class RoutingTestCase:
    def test_dispatcher_add(self):
        dispatcher = futurefinity.routing.Dispatcher()

        dispatcher.add(
            r"/", "a", "b", "c", Handler=futurefinity.web.RequestHandler,
            name="root", d="e")

        assert "root" in dispatcher._name_dict.keys()

        rule = dispatcher._name_dict["root"]

        assert "root" in dispatcher._name_dict.keys()
        assert rule.path == re.compile(r"/")

        assert rule.Handler is futurefinity.web.RequestHandler
        assert rule.path_args == ["a", "b", "c"]
        assert rule.path_kwargs == {"d": "e"}

    def test_dispatcher_find(self):
        dispatcher = futurefinity.routing.Dispatcher()

        dispatcher.add(r"/(.*?)/(?P<d>.*?)/(?P<f>.*?)", "a", "b", "c",
                       Handler=futurefinity.web.RequestHandler, d="e")

        Handler, args, kwargs = dispatcher.find("/asdf/ghjk/qwerty")

        assert Handler is futurefinity.web.RequestHandler
        assert args == ["a", "b", "c", "asdf", "ghjk", "qwerty"]
        assert kwargs == {"d": "e", "f": "qwerty"}

    def test_dispatcher_find_default(self):
        dispatcher = futurefinity.routing.Dispatcher(
            DefaultHandler=futurefinity.web.RequestHandler)

        class SubHandler(futurefinity.web.RequestHandler):
            pass

        dispatcher.add(path=r"/a", Handler=SubHandler)

        Handler, args, kwargs = dispatcher.find("/b")

        assert Handler is futurefinity.web.RequestHandler
        assert args == []
        assert kwargs == {}

    def test_dispatcher_find_no_default_raised(self):
        dispatcher = futurefinity.routing.Dispatcher()

        class SubHandler(futurefinity.web.RequestHandler):
            pass

        dispatcher.add(path=r"/a", Handler=SubHandler)

        with pytest.raises(futurefinity.routing.NoMatchesFound):
            dispatcher.find("/b")

    def test_dispatcher_reverse_positional(self):
        dispatcher = futurefinity.routing.Dispatcher()

        dispatcher.add(r"/(.*?)/(?P<d>.*?)/(?P<f>.*?)",
                       Handler=futurefinity.web.RequestHandler, name="test")

        assert "/asdf/ghjk/qwerty" == dispatcher.reverse(
            name="test", path_args=["asdf", "ghjk", "qwerty"])

    def test_dispatcher_reverse_positional(self):
        dispatcher = futurefinity.routing.Dispatcher()

        dispatcher.add(r"/(?P<a>.*?)/(?P<b>.*?)/(?P<c>.*?)",
                       Handler=futurefinity.web.RequestHandler, name="test")

        assert "/asdf/ghjk/qwerty" == dispatcher.reverse(
            name="test", path_kwargs={"a": "asdf", "b": "ghjk", "c": "qwerty"})
