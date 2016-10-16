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

from .utils import InvalidStatementOperation, ParseError, is_allowed_name
from futurefinity.utils import ensure_str, TYPE_CHECKING, Text

from typing import Optional, Union

import typing

if TYPE_CHECKING:
    from . import printer


class StatementModifier:
    """
    The Statement Modifier.

    It supports two types of modifier `async` and `from`.

    The `from` modifier will take 1 argument off from the statement, however
    `async` modifier will not take any arguments off from the statement.
    """
    _modifier_args = {
        "async": 0,
        "from": 1
    }

    def __init__(self, keyword: Text, rest: Optional[Text]=None):
        self._keyword = keyword
        self._rest = rest.strip() if rest else ""

    @staticmethod
    def parse_modifier(smt_str: Text) -> (Optional["StatementModifier"], Text):
        """
        Parse the statement modifier from the statement string if it has one.
        """
        _splitted = smt_str.strip().split(" ", maxsplit=1)

        if _splitted[0] not in StatementModifier._modifier_args.keys():
            return (None, smt_str)

        rest_str = _splitted[1]

        modifier_keyword = _splitted[0].strip()
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

    def gen_modifier(self) -> Text:
        return "{} {}".format(self._keyword, self._rest).strip()


class Statement:
    """
    The base statement.

    All the statements should be a sub class of this class.
    """
    _keywords = ()

    def __init__(self,
                 keyword: Optional[Text]=None,
                 rest: Optional[Text]=None,
                 modifier: Optional[StatementModifier]=None,
                 smt_at: Union[int, str]="<unknown>"):
        self._statements = []
        self._finished = False

        self._keyword = keyword or ""
        self._rest = rest.strip() if rest else ""
        self._modifier = modifier

        self._smt_at = smt_at

        self._should_indent = False

        self._should_append = True

        self._should_unindent = False

    def raise_invalid_operation(
     self, message: Text, from_err: Optional[Exception]=None):
        err_str = "{} at line {}.".format(message, self._smt_at)
        if from_err:
            raise InvalidStatementOperation(err_str) from from_err
        else:
            raise InvalidStatementOperation(err_str)

    @property
    def should_indent(self) -> bool:
        """
        Check if this is a indent block.
        """
        return self._should_indent

    @property
    def should_append(self) -> bool:
        """
        Check if this should be append to the current indent.
        """
        return self._should_append

    @property
    def should_unindent(self) -> bool:
        """
        Check if this should be removed from the indents when finishing.
        """
        return self._should_unindent

    def append_statement(self, smt: "Statement"):
        """
        Append a statement to the current statement.
        """
        if self._finished:
            self.raise_invalid_operation(
                "This statement has already been finished")

        if not self.should_indent:
            self.raise_invalid_operation(
                "This statement is not an indent statement")

        self._statements.append(smt)

    def unindent(self):
        """
        Unindent a statement.
        """
        if self._finished:
            self.raise_invalid_operation(
                "This statement has already been finished")

        if not self.should_indent:
            self.raise_invalid_operation(
                "This statement is not an indent statement")

        self._finished = True

    def print_code(self, code_printer: "printer.CodePrinter"):
        """
        Print the code to the printer.
        """
        self.raise_invalid_operation(
            "Method print_code is not implemented",
            from_err=NotImplementedError())

    def gen_smt_code(self) -> Text:
        """
        Generate the statement string.
        """
        modifier = self._modifier.gen_modifier() if self._modifier else ""

        return "{} {} {}".format(modifier, self._keyword, self._rest).strip()


class RootStatement(Statement):
    """
    The Root statement.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._block_statements = {}

        self._should_indent = True

    @property
    def should_append(self) -> bool:
        self.raise_invalid_operation(
            "RootStatement cannot be appended to other statements")

    def append_block_statement(self, smt: "BlockStatement"):
        """
        Append a block to the root.

        The block should be appended to both the root and the current indent.
        """
        if smt.block_name in self._block_statements.keys():
            raise InvalidStatementOperation(
                "Block with name {} has already been defined."
                .format(smt.block_name))

        self._block_statements[smt.block_name] = smt

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "class __TplCurrentNamespace__(__TplNamespace__):",
            smt_at=self._smt_at)

        with code_printer.code_indent():
            code_printer.write_line(
                "async def _render_body_str(self) -> str:",
                smt_at=self._smt_at)

            with code_printer.code_indent():
                code_printer.write_line(
                    "__tpl_result__ = \"\"", smt_at=self._smt_at)

                for smt in self._statements:
                    smt.print_code(code_printer)

                code_printer.write_line(
                    "return __tpl_result__", smt_at=self._smt_at)

            for block_smt in self._block_statements.values():
                block_smt.print_block_code(code_printer)


class IncludeStatement(Statement):
    """
    The Statement represents the include statement.

    Keyowrd: `include`.
    """
    _keywords = ("include", )

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "__tpl_result__ += await self._include_tpl({})".format(self._rest),
            smt_at=self._smt_at)


class InheritStatement(Statement):
    """
    The Statement represents the inherit statement.

    Keyword: `inherit`.
    """
    _keywords = ("inherit", )

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "await self._add_parent({})".format(self._rest),
            smt_at=self._smt_at)


class BlockStatement(Statement):
    """
    The Statement represents the block statement.
    """
    _keywords = ("block",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

        self._block_name = self._rest.strip()

        if not is_allowed_name(self._block_name):
            raise ParseError(
                "Invalid Block Statement. Block Name expected, got: {} {}."
                .format(self._keyword, self._rest))

    @property
    def block_name(self):
        """
        Return the block name.
        """
        return self._block_name

    def print_block_code(self, code_printer: "printer.CodePrinter"):
        """
        Print the actual block code.
        """
        code_printer.write_line("@staticmethod", smt_at=self._smt_at)
        code_printer.write_line("async def _render_block_{}_str(self) -> str:"
                                .format(self._block_name), smt_at=self._smt_at)

        with code_printer.code_indent():
            code_printer.write_line(
                "__tpl_result__ = \"\"", smt_at=self._smt_at)
            for smt in self._statements:
                smt.print_code(code_printer)
            code_printer.write_line(
                "return __tpl_result__", smt_at=self._smt_at)

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "__tpl_result__ += await self.blocks.{}(_defined_here=True)"
            .format(self._block_name), smt_at=self._smt_at)


class IndentStatement(Statement):
    """
    The Statement represents the indent statement.

    Keywords: `if`, `with`, `for`, `while`, and `try`.
    """
    _keywords = ("if", "with", "for", "while", "try")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_indent = True

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "{}:".format(self.gen_smt_code()), smt_at=self._smt_at)

        with code_printer.code_indent():
            for smt in self._statements:
                smt.print_code(code_printer)

            code_printer.write_line("pass")
            # In case there's nothing inside the indent.


class UnindentStatement(Statement):
    """
    The Statement represents the unindent statement.

    Unindent the last indent.

    Keyword: `end`.
    """
    _keywords = ("end",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._should_unindent = True
        self._should_append = False


class HalfIndentStatement(UnindentStatement, IndentStatement):
    """
    The Statement represents the half-indent statement.

    Automatically unindent the last indent and establish a new indent.

    Keywords: `else`, `elif`, `except`, and `finally`.
    """
    _keywords = ("else", "elif", "except", "finally")

    def __init__(self, *args, **kwargs):
        Statement.__init__(self, *args, **kwargs)

        self._should_indent = True
        self._should_unindent = True


class InlineStatement(Statement):
    """
    The Statement represents the inline statement.

    Keywords: `break`, `continue`, `import`, and `raise`.
    """
    _keywords = ("break", "continue", "import", "raise")

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(self.gen_smt_code(), smt_at=self._smt_at)


class OutputStatement(Statement):
    """
    The Statement represents the inline statement.

    Output the result to the result.

    Keywords: `=`, `r=`, `raw=`, `u=`, `url=`, `j=`, `json=`, `h=`,
    and `html=`.

    `=` represents the default escape. The default escape preferred by the
    templating system is html escape.

    `r=` and `raw=` represent to output the raw string with no escape.

    `h=` and `html=` represent to output the string with html escape.

    `u=` and `url=` represent to output the string with url escape.

    `j=` and `json=` represent to output the string with json escape.
    """
    _keywords = ("=", "r=", "raw=", "u=", "url=", "j=", "json=", "h=", "html=")

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "__tpl_output_raw_result__ = __tpl_ensure_str__({})".format(
                self._rest),
            smt_at=self._smt_at)

        if self._keyword == "=":
            code_printer.write_line(
                "__tpl_output_result__ = "
                "self.default_escape(__tpl_output_raw_result__)",
                smt_at=self._smt_at)

        elif self._keyword in ("r=", "raw="):
            code_printer.write_line(
                "__tpl_output_result__ = "
                "self.no_escape(__tpl_output_raw_result__)",
                smt_at=self._smt_at)

        elif self._keyword in ("u=", "url="):
            code_printer.write_line(
                "__tpl_output_result__ = "
                "self.escape_url(__tpl_output_raw_result__)",
                smt_at=self._smt_at)

        elif self._keyword in ("j=", "json="):
            code_printer.write_line(
                "__tpl_output_result__ = "
                "self.escape_json(__tpl_output_raw_result__)",
                smt_at=self._smt_at)

        elif self._keyword in ("h=", "html="):
            code_printer.write_line(
                "__tpl_output_result__ = "
                "self.escape_html(__tpl_output_raw_result__)",
                smt_at=self._smt_at)

        else:
            raise CodeGenerationError(
                "Unknown Type of Output: {}".format(self._keyword))

        code_printer.write_line(
            "__tpl_result__ += __tpl_output_result__",
            smt_at=self._smt_at)


class StrStatement(Statement):
    """
    The Statement represents the string in the template.
    """
    def __init__(self, smt_str: Text, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._smt_str = smt_str

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "__tpl_result__ += {}".format(repr(ensure_str(self._smt_str))),
            smt_at=self._smt_at)

class CommentStatement(Statement):
    """
    The statement represents the comment in the template.

    Keyword: `#`.
    """
    _keywords = ("#",)

    def print_code(self, code_printer: "printer.CodePrinter"):
        pass  # Just Print Nothing.


class CodeStatement(Statement):
    """
    The statement represents the code in the template.

    This allows you to execute arbitrary **inline** code in your template.

    Keyword: `@`.
    """
    _keywords = ("@",)

    def print_code(self, code_printer: "printer.CodePrinter"):
        code_printer.write_line(
            "{}".format(self._rest), smt_at=self._smt_at)

builtin_statements = (
    OutputStatement, IndentStatement, HalfIndentStatement,
    IncludeStatement, BlockStatement, UnindentStatement,
    InlineStatement, InheritStatement, CommentStatement,
    CodeStatement)
