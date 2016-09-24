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

from .utils import CodeGenerationError

from typing import Optional

import types


class CodePrinter:
    def __init__(
        self, top_indent: int=0,
        template_name: Optional[str]=None,
        indent_mark: str="    ", end_of_line: str="\n",
            result_var: str="self.__tpl_result__"):

        self._indent_num = top_indent
        self._template_name = template_name
        self._indent_mark = indent_mark
        self._end_of_line = end_of_line
        self._result_var = result_var

        self._committed_code = ""

        self._finished = False

    def code_indent(self) -> "CodePrinter":
        if self._finished:
            raise CodeGenerationError

        return self

    def __enter__(self):
        self._inc_indent_num()

    def __exit__(self, *exc):
        self._dec_indent_num()

    def _inc_indent_num(self):
        if self._finished:
            raise CodeGenerationError

        self._indent_num += 1

    def _dec_indent_num(self):
        if self._finished:
            raise CodeGenerationError

        self._indent_num -= 1

    def write_line(self, line_str: str):
        if self._finished:
            raise CodeGenerationError

        self._committed_code += self._indent_mark * self._indent_num

        self._committed_code += line_str

        self._committed_code += self._end_of_line

    def append_result(self, line_str: str):
        self.write_line(self._result_var + " += " + line_str)

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def plain_code(self) -> str:
        self._finished = True
        return self._committed_code

    @property
    def compiled_code(self) -> types.CodeType:
        if not hasattr(self, "_compiled_code"):
            self._compiled_code = compile(
                self.plain_code,
                "<Template: {}>".format(self._template_name), "exec",
                dont_inherit=True)

        return self._compiled_code
