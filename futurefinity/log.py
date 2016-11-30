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
``futurefinity.log`` contains the logging facility used by futurefinity.

"""

from typing import Union, Callable
from . import compat

import sys
import logging
import warnings

try:
    import curses
    curses.setupterm()
    if sys.stderr.isatty() and curses.tigetnum("colors") > 0:
        _color_term_supported = True
    else:
        _color_term_supported = False

    del curses

except:
    _color_term_supported = False

if compat.TYPE_CHECKING:
    T = Callable[[], logging.Logger]
    T2 = Callable[[compat.Text], logging.Logger]

get_logger = getattr(logging, "getLogger")  # type: T


class TermColors:
    """
    Enum of Terminal Colors.

    black = 0
    red = 1
    green = 2
    yellow = 3
    blue = 4
    magenta = 5
    cyan = 6
    white = 7
    default = 9
    """
    black = 0
    red = 1
    green = 2
    yellow = 3
    blue = 4
    magenta = 5
    cyan = 6
    white = 7
    default = 9


def gen_color_code(color_num: int, is_bg: bool=False) -> compat.Text:
    """
    Return proper color code based on `color_num` from :class:`.TermColors`.
    """
    if color_num == -1:
        return "\033[0m"  # Reset the term.

    color_num += 30

    if is_bg:
        color_num += 10

    return "\033[{}m".format(color_num)


class _LoggingFmt(str):
    def __init__(self, *args, **kwargs):
        super().__init__()

        self._colors = {
            "DEBUG": TermColors.blue,
            "INFO": TermColors.green,
            "WARNING": TermColors.yellow,
            "ERROR": TermColors.red,
            "CRITICAL": TermColors.red
        }

        self._color_enabled = True

    def _color_levelname(self, levelname: compat.Text) -> compat.Text:
        if (self._color_enabled and _color_term_supported and
           levelname in self._colors.keys()):

            return gen_color_code(self._colors[levelname]) + \
                levelname + gen_color_code(-1)

        return levelname

    def set_level_color(self, levelname: compat.Text, color: int):
        self._colors[levelname] = color

    def enable_color(self):
        self._color_enabled = True

    def disable_color(self):
        self._color_enabled = False

    def format(self, *args, **kwargs) -> compat.Text:
        fmt_kwargs = {}
        fmt_kwargs.update(**kwargs)

        if "levelname" in fmt_kwargs.keys():
            fmt_kwargs["levelname"] = self._color_levelname(
                fmt_kwargs["levelname"])

        return str(self).format(*args, **fmt_kwargs)


def set_log_level(
    logger: Union[logging.Logger, logging.StreamHandler],
        lvl: int):
    """
    Set the log level of a logger.
    """
    set_level = getattr(logger, "setLevel")

    set_level(lvl)

default_fmt = _LoggingFmt("{asctime} - {name} - {levelname} - {message}")

formatter = logging.Formatter(
    default_fmt,
    datefmt="%Y-%m-%d %H:%M:%S",
    style="{")

channel = logging.StreamHandler()
getattr(channel, "setFormatter")(formatter)
set_log_level(channel, logging.DEBUG)

global_log = get_logger("futurefinity")  # type: logging.Logger
set_log_level(global_log, logging.INFO)

getattr(global_log, "addHandler")(channel)

get_child_logger = getattr(global_log, "getChild")  # type: T2
