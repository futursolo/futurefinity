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

from .utils import InvalidStatementOperation
from futurefinity.utils import ensure_str

from typing import Optional

import typing

if hasattr(typing, "TYPE_CHECKING") and typing.TYPE_CHECKING:
    from . import printer


class StatementModifier:
    _modifier_args = {
        "async": 0,
        "from": 1
    }

    def __init__(self, keyword: str, rest: Optional[str]=None):
        self._keyword = keyword
        self._rest = rest.strip() if rest else ""

    @staticmethod
    def parse_modifier(smt_str: str) -> (Optional["StatementModifier"], str):

        _splitted = smt_str.strip().split(" ", maxsplit=1)

        if _splitted[0] not in StatementModifier._modifier_args.keys():
            return (None, smt_str)

        rest_str = _splitted[1]

        modifier_keyword = _splitted[0]
        modifier_rest = ""

        for _ in range(0, StatementModifier._modifier_args[modifier_keyword]):
            _splitted = rest_str.strip().split(" ", maxsplit=1)

            if len(_splitted) < 2:
                raise ParseError(
                    ("Not Suffient Modifier Argument(s). "
                     "{} modifier is expecting {} arguments.").format(
                        modifier_keyword,
                        StatementModifier._modifier_args[modifier_keyword]))

            modifier_rest += " " + _splitted[0]

            rest_str = _splitted[1]

        return (StatementModifier(modifier_keyword, modifier_rest), rest_str)

    def gen_modifier(self) -> str:
        return "{} {}".format(self._keyword, self._rest).strip()


class Statement:
    _keywords = ()

    def __init__(self,
                 keyword: Optional[str]=None,
                 rest: Optional[str]=None,
                 modifier: Optional[StatementModifier]=None,
                 smt_at: Optional[int]=None):
        self._statements = []
        self._finished = False

        self._keyword = keyword or ""
        self._rest = rest.strip() if rest else ""
        self._modifier = modifier

        self._smt_at = smt_at

        self._should_indent = False

        self._should_append = True

        self._should_unindent = False

    @property
    def should_indent(self) -> bool:
        return self._should_indent

    @property
    def should_append(self) -> bool:
        return self._should_append

    @property
    def should_unindent(self) -> bool:
        return self._should_unindent

    def append_statement(self, smt: "Statement"):
        if not self.should_indent or self._finished:
            raise InvalidStatementOperation

        self._statements.append(smt)

    def unindent(self):
        if not self.should_indent or self._finished:
            raise InvalidStatementOperation

        self._finished = True

    def print_code(self, code_printer: "printer.CodePrinter"):
        raise NotImplementedError

    def gen_smt_code(self) -> str:
        modifier = self._modifier.gen_modifier() if self._modifier else ""

        return "{} {} {}".format(modifier, self._keyword, self._rest).strip()

    @staticmethod
    def parse_statement(smt_str: str, smt_at: int) -> "Statement":
        modifier, rest_str = StatementModifier.parse_modifier(smt_str)

        splitted_smt_str = rest_str.strip().split(" ", 1)

        keyword = splitted_smt_str[0]

        if len(splitted_smt_str) > 1:
            rest = splitted_smt_str[1]
        else:
            rest = None

        for SmtClass in (
            OutputStatement, IndentStatement, HalfIndentStatement,
            IncludeStatement, BlockStatement, UnindentStatement,
                InlineStatement, InheritStatement):

            if keyword in SmtClass._keywords:
                return SmtClass(
                    keyword, rest, modifier, smt_at=smt_at)

        else:
            raise ParseError("Unknown Statement Keyword: {}.".format(keyword))


class RootStatement(Statement):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._blocks = {}

        self._should_indent = True

    @property
    def should_append(self) -> bool:
        raise InvalidStatementOperation(
            "_TemplateRootSmt cannot be appended to other statements.")

    def add_block(block: "_TemplateBlockSmt"):
        if block.block_name in self._blocks.keys():
            raise InvalidStatementOperation(
                "Block with name {} has already been defined."
                .format(block.block_name))

        self._blocks[block.block_name] = block

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "class CurrentTplNameSpace(_TemplateNamespace):")

        with code_printer.code_indent():
            code_printer.write_line("async def _render(self):")

            with code_printer.code_indent():
                for smt in self._statements:
                    smt.print_code(code_printer)

                code_printer.write_line("await self._inherit_tpl()")
                code_printer.write_line("self._finished = True")


class IncludeStatement(Statement):
    _keywords = ("include", )

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "await self._include_tpl({})".format(self._rest))


class InheritStatement(Statement):
    _keywords = ("inherit", )

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "await self._add_parent({})".format(self._rest))


class BlockStatement(Statement):
    _keywords = ("block",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

        self._block_name = self._rest.strip()

        if re.fullmatch(_ALLOWED_NAME, self._block_name) is None:
            raise ParseError(
                "Invalid Block Statement. Block Name expected, got: {} {}."
                .format(self._keyword, self._rest))

    @property
    def block_name(self):
        return self._block_name

    def print_block_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line("async def __tpl_render_block__(self):")

        with code_printer.code_indent():
            code_printer.write_line("__tpl_result__ = \"\"")
            for smt in self._statements:
                smt.print_code(code_printer)
            code_printer.write_line("return __tpl_result__")

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.append_result(
            "await self.blocks.{}(_defined_here=True)".format(
                self._block_name))


class IndentStatement(Statement):
    _keywords = ("if", "with", "for", "while", "try")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line("{}:".format(self.gen_smt_code()))

        with code_printer.code_indent():
            for smt in self._statements:
                smt.print_code(code_printer)


class UnindentStatement(Statement):
    _keywords = ("end",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_unindent = True
        self._should_append = False


class HalfIndentStatement(UnindentStatement, IndentStatement):
    _keywords = ("else", "elif", "except", "finally")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True
        self._should_unindent = True


class InlineStatement(Statement):
    _keywords = ("break", "continue", "import")

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(self.gen_smt_code())


class OutputStatement(Statement):
    _keywords = ("=", "r=", "raw=", "u=", "url=", "j=", "json=", "h=", "html=")

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "__tpl_output_raw_result__ = {}".format(self._rest))

        if self._keyword == "=":
            code_printer.write_line(
                "__tpl_output_result__ = \
                    self.default_escape(__tpl_output_raw_result__)")

        elif self._keyword in ("r=", "raw="):
            code_printer.write_line(
                "__tpl_output_result__ = \
                self.no_escape(__tpl_output_raw_result__)")

        elif self._keyword in ("u=", "url="):
            code_printer.write_line(
                "__tpl_output_result__ = \
                    self.escape_url(__tpl_output_raw_result__)")

        elif self._keyword in ("j=", "json="):
            code_printer.write_line(
                "__tpl_output_result__ = \
                    self.escape_json(__tpl_output_raw_result__)")

        elif self._keyword in ("h=", "html="):
            code_printer.write_line(
                "__tpl_output_result__ = \
                    self.escape_html(__tpl_output_raw_result__)")

        else:
            raise CodeGenerationError(
                "Unknown Type of Output: {}".format(self._keyword))

        code_printer.append_result("__tpl_output_result__")


class StrStatement(Statement):
    def __init__(self, smt_str: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._smt_str = smt_str

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.append_result(repr(ensure_str(self._smt_str)))
