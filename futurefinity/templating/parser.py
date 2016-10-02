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

from .utils import ParseError, ReadFinished
from futurefinity.utils import TYPE_CHECKING, Text

from . import statement

from typing import Union, Optional

if TYPE_CHECKING:
    from . import template

_BEGIN_MARK = "<%"
_END_MARK = "%>"
_ESCAPE_MARK = "%"


class TemplateParser:
    def __init__(self, tpl: "template.Template"):
        self._tpl = tpl

        self._splitted = self._tpl._tpl_str.splitlines(keepends=True)

        self._current_at = 0
        self._current_line = ""

        self._finished = False

        self._parse()

    def raise_parse_error(self, message: Text,
                          line: Union[int, Text]="<unknown>",
                          from_err: Optional[Exception]=None):
        err_str = "{} in file {} at line {}.".format(
            message, self._tpl._template_path, line)

        if from_err:
            raise ParseError(err_str) from from_err
        else:
            raise ParseError(err_str)

    @property
    def root(self) -> statement.RootStatement:
        if not self._finished:
            self.raise_parse_error(
                "Root is not Ready yet", self.current_at)

        return self._root

    def _move_to_next_line(self):
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        if self._current_line:
            self.raise_parse_error(
                "Parsing of last line is not completed", self.current_at)

        if not self._splitted:
            raise ReadFinished

        self._current_at += 1
        self._current_line = self._splitted.pop(0)

    def _find_next_begin_mark(self) -> int:
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        start_pos = 0

        while True:
            pos = self._current_line.find(_BEGIN_MARK, start_pos)

            if pos == -1:
                return -1

            elif self._current_line[pos + len(_BEGIN_MARK):].startswith(
             _ESCAPE_MARK):
                start_pos = pos + len(_BEGIN_MARK)
                end_pos = start_pos + len(_ESCAPE_MARK)

                self._current_line = (
                    self._current_line[:start_pos] +
                    self._current_line[end_pos:])

                continue

            else:
                return pos

    def _find_next_end_mark(self) -> int:
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        start_pos = 0

        while True:
            pos = self._current_line.find(_END_MARK, start_pos)

            if pos == -1:
                return -1

            elif pos == 0:
                return 0

            elif self._current_line[:pos].endswith(_ESCAPE_MARK):
                start_pos = pos - len(_ESCAPE_MARK)
                end_pos = pos

                self._current_line = (
                    self._current_line[:start_pos] +
                    self._current_line[end_pos:])

                start_pos = pos + len(_END_MARK)

                continue

            else:
                return pos

    @property
    def current_at(self) -> int:
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        return self._current_at

    def _append_to_current(self, smt: statement.Statement):
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        if not smt:
            return

        if self._indents:
            self._indents[-1].append_statement(smt)

        else:
            self._root.append_statement(smt)

    def _unindent_current(self):
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        if self._indents:
            self._indents.pop().unindent()

        else:
            self.raise_parse_error(
                "Redundant Unindent Statement", self.current_at)

    def _find_next_statement(self) -> Union[statement.Statement, Text]:
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        smt_str = ""
        begin_mark_line_no = -1

        while True:
            if not self._current_line:
                try:
                    self._move_to_next_line()

                except ReadFinished as e:
                    if begin_mark_line_no != -1:
                        self.raise_parse_error(
                            "Cannot find statement end mark "
                            "for begin mark", begin_mark_at, from_err=e)

                    elif smt_str:
                        return smt_str

                    else:
                        raise

            if begin_mark_line_no == -1:
                begin_mark_pos = self._find_next_begin_mark()

                if begin_mark_pos == -1:
                    smt_str += self._current_line
                    self._current_line = ""

                    continue

                elif begin_mark_pos > 0:
                    smt_str += self._current_line[:begin_mark_pos]
                    self._current_line = self._current_line[begin_mark_pos:]

                    return smt_str

                elif smt_str:
                    return smt_str

                begin_mark_line_no = self.current_at
                self._current_line = self._current_line[2:]

            end_mark_pos = self._find_next_end_mark()

            if end_mark_pos == -1:
                smt_str += self._current_line
                self._current_line = ""

                continue

            smt_str += self._current_line[:end_mark_pos]
            self._current_line = self._current_line[end_mark_pos + 2:]

            try:
                return statement.Statement.parse_statement(
                    smt_str, smt_at=self._current_at)
            except Exception as e:
                self.raise_parse_error(
                    "Error Occurred when parsing statememt", from_err=e)

    def _parse(self):
        if self._finished:
            raise ParseError("Parsing has already been finished.")

        self._root = statement.RootStatement()
        self._indents = []

        while True:
            try:
                smt = self._find_next_statement()

            except ReadFinished:
                break

            if isinstance(smt, str):
                self._append_to_current(statement.StrStatement(
                    smt, smt_at=self.current_at))
                continue

            try:
                if smt.should_unindent:
                    self._unindent_current()

                if smt.should_append:
                    self._append_to_current(smt)

                if smt.should_indent:
                    self._indents.append(smt)

                if isinstance(smt, statement.BlockStatement):
                    self._root.append_block_statement(smt)

            except Exception as e:
                self.raise_parse_error(
                    "Error Occurred when dealing with statememt", from_err=e)

        if self._indents:
            self.raise_parse_error(
                "Unindented Indent Statement",
                line=self._indents[-1]._smt_at)

        self._root.unindent()
        self._finished = True
