#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2015 Futur Solo
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


from futurefinity.utils import MagicDict
from futurefinity.utils import ensure_str, ensure_bytes, split_data, MagicDict


import io
import typing
import http.cookies
import urllib.parse


_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"

_MAX_HEADER_NUMBER = 4096

_MAX_HEADER_LENGTH = 4096

_MAX_BODY_LENGTH = 52428800  # 50M

_REQUEST_WAITING_HEADER = 0
_REQUEST_HEADER_FINISHED = 1
_REQUEST_WAITING_BODY = 2
_REQUEST_FINISHED = 3

_SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PATCH", "PUT",
                      "OPTIONS", "CONNECT")
_BODY_EXPECTED_METHODS = ("POST", "PATCH", "PUT")


class HTTPError(Exception):
    """
    Common HTTPError class, this Error should be raised when a non-200 status
    need to be responded.

    Any additional message can be added to the response by message attribute.

    .. code-block:: python3

      async def get(self, *args, **kwargs):
          raise HTTPError(500, message='Please contact system administor.')

    """
    def __init__(self, status_code: int=200, message: str=None,
                 *args, **kwargs):
        self.status_code = status_code
        self.message = message


class HTTPHeaders(MagicDict):
    """
    HTTPHeaders class, based on MagicDict. But Keys must be str and are
    case-insensitive.
    """
    def add(self, name: str, value: str):
        """
        Add a header and change the name to lowercase.
        """
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name: str, default: typing.Optional[str]=None):
        """
        Get all headers with the name in a list.
        """
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def get_first(self, name: str, default: typing.Optional[str]=None):
        """
        Get first header with the name.
        """
        lower_name = name.lower()
        return MagicDict.get_first(self, lower_name, default=default)

    def __setitem__(self, name, value):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def __repr__(self):
        return "HTTPHeaders()"

    def __str__(self):
        content_list = []
        for key, value in self.items():
            content_list.append((key, value))

        return "HTTPHeaders(%s)" % str(content_list)

    def copy(self):
        """
        Create another instance of HTTPHeaders but contains the same content.
        """
        return HTTPHeaders(self)

    def parse_http_v1_header(self, data: typing.Union[str, bytes, io.StringIO],
                             use_crlf_mark: bool=True):
        """
        Parse HTTP/1.x HTTP Header and return an HTTPHeader instance.
        """
        if isinstance(data, io.StringIO):
            data_io = data
        elif isinstance(data, bytes):
            data_io = io.StringIO(data.decode())
        elif isinstance(data, str):
            data_io = io.StringIO(data)

        for i in range(0, _MAX_HEADER_NUMBER):
            header = data_io.readline().replace("\r", "").replace("\n", "")
            if not header:
                break
            (key, value) = header.split(":", 1)
            self.add(key.strip(), value.strip())

    __copy__ = copy


class HTTPCookies:
    pass


class HTTPFile:
    pass


class HTTPBody:
    pass


class HTTPRequest:
    def __init__(self, path: str=None, host: str="", method: str="GET",
                 http_version: int=None,
                 headers: typing.Optional[HTTPHeaders]=None,
                 cookies: typing.Optional[HTTPCookies]=None,
                 body: typing.Optional[HTTPBody]=None):
        if path is None:
            self.stage = _REQUEST_WAITING_HEADER
            self.http_version = None
        else:
            self.stage = _REQUEST_FINISHED
            self.http_version = http_version or 10
        self._pending_bytes = b""
        self._crlf_mark = None
        self.path = path
        self.method = method
        self.host = host
        self.parsed_path = None
        self.queries = MagicDict()
        self.http_version = http_version or 10
        self.cookies = cookies or HTTPCookies()
        self.headers = headers or HTTPHeaders()
        self.body = body or HTTPBody()

    def decide_http_v1_mark(self):
        """
        Decide the request is CRLF or LF.

        Return None if the request is still not finished.
        Return True if CRLF is used.
        Return False if LF is used.

        Raise an HTTPError(413) if Header is larger than _MAX_HEADER_LENGTH.
        """
        crlf_position = self._pending_bytes.find(_CRLF_BYTES_MARK * 2)
        lf_position = self._pending_bytes.find(_LF_BYTES_MARK * 2)

        if (crlf_position == -1 and lf_position == -1) and len(
           self._pending_bytes) < _MAX_HEADER_LENGTH:
            self._crlf_mark = None  # Request Not Completed, wait.
        elif crlf_position != -1 and lf_position != -1:
            if lf_position > crlf_position:
                self._crlf_mark = True
            self._crlf_mark = False
        elif crlf_position != -1:
            self._crlf_mark = True
        elif lf_position != -1:
            self._crlf_mark = False
        else:
            raise HTTPError(413)  # 413 Request Entity Too Large

    def parse_request(self, request_bytes: bytes) -> bool:
        self._pending_bytes += request_bytes

        if self.stage == _REQUEST_WAITING_HEADER:
            self.decide_http_v1_mark()
            if self._crlf_mark is None:
                return False  # Request Not Completed, wait.
            else:
                raw_initial, self._pending_bytes = split_data(
                    self._pending_bytes, use_crlf_mark=self._crlf_mark,
                    mark_repeat=2, max_part=2)
                raw_initial = raw_initial.decode()

                basic_info, headers = split_data(raw_initial,
                                                 use_crlf_mark=self._crlf_mark,
                                                 max_part=2)

                basic_info = basic_info.split(" ")

                if len(basic_info) != 3:
                    raise HTTPError(400)  # 400 Bad Request

                method, path, http_version = basic_info

                if http_version.lower() == "http/1.1":
                    self.http_version = 11
                elif http_version.lower() == "http/1.0":
                    self.http_version = 10
                else:
                    raise HTTPError(400)  # 400 Bad Request

                self.headers.parse_http_v1_header(headers)

                self.path = path
                self.method = method
                self.host = self.headers.pop("host")

                if "cookie" in self.headers:
                    self.cookies = http.cookies.SimpleCookie(
                        self.headers.get_first("cookie"))
                else:
                    self.cookies = http.cookies.SimpleCookie()

                parsed_url = urllib.parse.urlparse(self.path)
                self.parsed_path = parsed_url.path

                for query in urllib.parse.parse_qsl(parsed_url.query):
                    self.queries.add(query[0], query[1])

                if self.method in _BODY_EXPECTED_METHODS:
                    if int(self.headers.get_first(
                     "content-length")) > _MAX_BODY_LENGTH:
                        raise HTTPError(413)  # 413 Request Entity Too Large
                else:
                    return True

    def generate_bytes(self):
        pass


class HTTPResponse:
    pass
