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

from futurefinity.utils import *
try:
    import jinja2
except ImportError:
    jinja2 = None


DefaultTemplateInterface = None


class TemplateInterfaceModel:
    """
    Model Of all the Template Interface.
    """
    def __init__(self, app=None, template_path=None, *args, **kwargs):
        self.app = app
        self.template_path = template_path
        self.envir = None
        self._initialized = False

    def initialize(self, app=None):
        if self._initialized:
            return
        if app:
            self.app = app
        if not self.app:
            raise Exception(
                "FutureFinity Application is not set for this Interface.")
        self._initialized = True

        if self.template_path is None:
            self.template_path = self.app.settings.get("template_path", None)

    def render_template(self, template_name, template_args):
        raise NotImplementedError("No Template Rendering Engine Installed!")


class Jinja2TemplateInterface(TemplateInterfaceModel):
    def __init__(self, app=None, template_path=None, *args, **kwargs):
        TemplateInterfaceModel.__init__(self, app, template_path,
                                        *args, **kwargs)

        if jinja2 is None:
            raise Exception("Jinja2 is not installed; however, "
                            "Jinja2TemplateInterface is selected.")

    def initialize(self, app):
        TemplateInterfaceModel.initialize(self, app)
        if self.template_path is None:
            return
        self.envir = jinja2.Environment(loader=jinja2.FileSystemLoader(
            self.template_path,
            encoding=self.app.settings.get("encoding", "utf-8")
        ))

    def render_template(self, template_name, template_dict):
        if self.envir is None:
            raise Exception(
                "Cannot found template_path. "
                "Please provide template_path through Application Settings or"
                " __init__ Parameter.")

        template = self.envir.get_template(template_name)
        return template.render(**template_dict)

if jinja2 is not None:
    DefaultTemplateInterface = Jinja2TemplateInterface
else:
    DefaultTemplateInterface = TemplateInterfaceModel
