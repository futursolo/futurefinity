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

from . import compat
from . import encoding
from . import magicdict

from typing import Optional, Union, Mapping

from http.cookies import SimpleCookie as HTTPCookies

import time
import numbers
import calendar
import datetime
import email.utils
import http.client

__all__ = ["HTTPCookies", "status_code_descriptions", "format_timestamp"]

status_code_descriptions = {
    int(key): value for key, value in http.client.responses.items()}
status_code_descriptions.setdefault(451, "Unavailable For Legal Reasons")


def format_timestamp(ts: Optional[Union[numbers.Real, tuple, time.struct_time,
                                  datetime.datetime]]=None) -> compat.Text:
    """
    Make a HTTP Protocol timestamp.
    """
    if ts is None:
        ts = time.time()

    if isinstance(ts, numbers.Real):
        pass

    elif isinstance(ts, (tuple, time.struct_time)):
        ts = calendar.timegm(ts)

    elif isinstance(ts, datetime.datetime):
        ts = calendar.timegm(ts.utctimetuple())

    else:
        raise TypeError("unknown timestamp type: {}".format(ts))

    return encoding.ensure_str(email.utils.formatdate(ts, usegmt=True))


def parse_semicolon_header(
        value: compat.Text) -> Mapping[compat.Text, Optional[compat.Text]]:
    header_dict = magicdict.TolerantMagicDict()
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        splitted = part.split("=", 1)
        part_name = splitted.pop(0)
        part_value = splitted.pop() if splitted else None
        if part_value:
            if part_value.startswith('"') and part_value.endswith('"'):
                part_value = part_value[1:-1]
        header_dict.add(part_name.strip(), part_value.strip())

    return header_dict


def build_semicolon_header(
    header_dict: Mapping[compat.Text, Optional[compat.Text]]
        ) -> compat.Text:
    header_list = []
    for name, value in header_dict.items():
        part = name.strip()
        if value is not None:
            part += "=" + value.strip()

        header_list.append(part)

    return "; ".join(header_list)
