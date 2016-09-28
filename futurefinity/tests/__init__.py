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

"""
FutureFinity Test Suite.
"""
from futurefinity.tests.__main__ import main
from setuptools.command.test import test as BaseTestCommand


class TestCommand(BaseTestCommand):
    user_options = [
        ("test-args=", "a", "Arguments to pass to Test Suite(pytest).")]

    def initialize_options(self):
        super().initialize_options()
        self.test_args = []

    def run_tests(self):
        main(self.test_args)
