#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
``futurefinity.interface`` contains the interface implementation of
FutureFinity. By replace default interfaces of FutureFinity, developer can
enhance the feature of FutureFinity.
"""

from futurefinity.utils import *
from futurefinity.interface import template as template_interface
from futurefinity.interface import session as session_interface

default_interfaces = {
    "template": template_interface.DefaultTemplateInterface,
    "session": session_interface.DefaultSessionInterface
}


class InterfaceFactory:
    def __init__(self, app, *args, **kwargs):
        self.app = app
        self._interfaces = {}
        self._initialized = False

    def initialize(self):
        if self._initialized:
            return
        self._initialized = True
        for key in default_interfaces.keys():
            if key not in self._interfaces.keys():
                self._interfaces[key] = default_interfaces[key]()

        for interface in self._interfaces.values():
            interface.initialize(app=self.app)

    def set(self, name, interface):
        if self._initialized:
            raise Exception(
                "InterfaceFactory is intialized. "
                "Custom interface must be setted before intialization.")
        self._interfaces[name] = interface

    def get(self, name):
        if not self._initialized:
            raise Exception(
                "InterfaceFactory is not intialized. "
                "This method must be called after initalization.")
        return self._interfaces[name]
