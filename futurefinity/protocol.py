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


from futurefinity.utils import (ensure_str, ensure_bytes,
                                MagicDict, TolerantMagicDict)

from http.cookies import SimpleCookie as HTTPCookies

import io
import typing

import urllib.parse

__all__ = ["HTTPCookies"]

_CR_MARK = "\r"
_CR_BYTES_MARK = b"\r"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"

_CRLF_MARK = _CR_MARK + _LF_MARK
_CRLF_BYTES_MARK = _CR_BYTES_MARK + _LF_BYTES_MARK

_CRLF_MARK_LIST = (_CR_MARK, _LF_MARK, _CRLF_MARK)
_CRLF_BYTES_MARK_LIST = (_CR_BYTES_MARK, _LF_BYTES_MARK, _CRLF_BYTES_MARK)

_MAX_HEADER_NUMBER = 4096

_MAX_HEADER_LENGTH = 4096

_MAX_BODY_LENGTH = 52428800  # 50M

_REQUEST_EMPTY = 0
_REQUEST_WAITING_INITIAL = 1
_REQUEST_WAITING_HEADER = 2
_REQUEST_WAITING_BODY = 3
_REQUEST_FINISHED = 4
_REQUEST_BROKEN = -1
_REQUEST_DESTROYED = -2

_SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PATCH", "PUT",
                      "OPTIONS", "CONNECT")
_BODY_EXPECTED_METHODS = ("POST", "PATCH", "PUT")


def _clear_crlf(content: typing.Union[str, bytes]) -> typing.Union[str, bytes]:
    if isinstance(content, str):
        if content[-1:] in _CRLF_MARK_LIST:
            content = content[:-1]
        if content[-1:] in _CRLF_MARK_LIST:
            content = content[:-1]
    else:
        if content[-1:] in _CRLF_BYTES_MARK_LIST:
            content = content[:-1]
        if content[-1:] in _CRLF_BYTES_MARK_LIST:
            content = content[:-1]
    return content


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


class HTTPHeaders(TolerantMagicDict):
    """
    HTTPHeaders class, based on MagicDict.

    It has not only all the features from TolerantMagicDict, but also
    can parse and make HTTP Headers.
    """
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

    def parse_http_v1_header(self, data: typing.Union[str, bytes, list]):
        """
        Parse HTTP/1.x HTTP Header.
        """
        if isinstance(data, list):
            splitted_data = data
        else:
            splitted_data = ensure_bytes(data).splitlines(keepends=True)

        for i in range(0, _MAX_HEADER_NUMBER + 1):
            if len(splitted_data) == 0:
                return False

            header = splitted_data.pop(0).decode()

            if header in _CRLF_MARK_LIST:
                return True

            header = _clear_crlf(header)
            (key, value) = header.split(":", 1)
            self.add(key.strip(), value.strip())

        else:
            raise HTTPError(413)  # Too many Headers.

        return False

    __copy__ = copy
    __repr__ = __str__


class HTTPFile:
    def __init__(self, filename: str, content: typing.Union[str, bytes],
                 content_type: str="application/octet-stream",
                 headers: typing.Optional[HTTPHeaders]=None,
                 encoding: str="binary"):
        self.filename = filename
        self.content = content
        self.content_type = content_type
        self.headers = headers or HTTPHeaders()
        self.encoding = encoding

    def __str__(self):
        return ("HTTPFile(filename=%(filename)s, "
                "content_type=%(content_type)s, "
                "headers=%(headers)s, "
                "encoding=%(encoding)s)") % {
                    "filename": repr(self.filename),
                    "content_type": repr(self.content_type),
                    "headers": repr(self.headers),
                    "encoding": repr(self.encoding)
                }


class HTTPBody(TolerantMagicDict):
    def __init__(self, *args, **kwargs):
        TolerantMagicDict.__init__(self, *args, **kwargs)
        self._content_length = 0
        self._content_type = ""
        self._pending_bytes = b""

    def set_content_length(self, content_length: int):
        self._content_length = content_length

    def get_content_length(self):
        return self._content_length

    def set_content_type(self, content_type: str):
        self._content_type = content_type

    def get_content_type(self):
        return self._content_type

    def __str__(self):
        content_list = []
        for key, value in self.items():
            content_list.append((key, value))

        return "HTTPBody(%s)" % str(content_list)

    def copy(self):
        """
        Create another instance of HTTPBody but contains the same content.
        """
        return HTTPBody(self)

    def parse_http_v1_body(self, data: typing.Union[str, bytes]) -> bool:
        self._pending_bytes += ensure_bytes(data)
        if len(self._pending_bytes) < self._content_length:
            return False  # Request Not Completed, wait.
        if self._content_type.lower().strip() in (
         "application/x-www-form-urlencoded", "application/x-url-encoded"):
            for (key, value) in urllib.parse.parse_qsl(
             self._pending_bytes[:self._content_length],
             keep_blank_values=True,
             strict_parsing=True):
                self.add(key.decode(), value.decode())

        elif self._content_type.lower().startswith("multipart/form-data"):
            for field in self._content_type.split(";"):  # Search Boundary
                if field.find("boundary=") == -1:
                    continue
                boundary = ensure_bytes(field.split("=")[1])
                if boundary.startswith(b'"') and boundary.endswith(b'"'):
                    boundary = boundary[1:-1]
                break
            else:
                raise HTTPError(400)  # Cannot Find Boundary
            full_boundary = b"--" + boundary
            body_content, body_crlf_mark = self._pending_bytes[
                :self._content_length].split(full_boundary + b"--")

            full_boundary += body_crlf_mark
            splitted_body_content = body_content.split(full_boundary)
            body_crlf_mark_length = len(body_crlf_mark)

            for part in splitted_body_content:
                if not part:
                    continue

                initial, splitter, content = part.partition(body_crlf_mark * 2)
                headers = HTTPHeaders()
                if not headers.parse_http_v1_header(initial + splitter):
                    raise HTTPError(400)  # 400 Bad Request.

                disposition = headers.get_first("content-disposition")
                disposition_list = []
                disposition_dict = TolerantMagicDict()

                for field in disposition.split(";"):  # Split Disposition
                    field = field.strip()  # Remove Useless Spaces.
                    if field.find("=") == -1:  # This is not a key-value pair.
                        disposition_list.append(field)
                        continue
                    key, value = field.split("=")
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    disposition_dict.add(key.strip().lower(), value.strip())

                if disposition_list[0] != "form-data":
                    raise HTTPError(400)
                    # Mixed form-data will be supported later.
                content = content[:-body_crlf_mark_length]  # Drop CRLF Mark

                if "filename" in disposition_dict.keys():
                    self.add(disposition_dict.get_first("name", ""), HTTPFile(
                        filename=disposition_dict.get_first("filename", ""),
                        content=content,
                        content_type=headers.get_first(
                            "content-type", "application/octet-stream"),
                        headers=headers,
                        encoding=headers.get_first("content-transfer-encoding",
                                                   "binary")
                    ))
                else:
                    try:
                        content = content.decode()
                    except UnicodeDecodeError:
                        pass
                    self.add(disposition_dict.get_first("name", ""), content)
        else:
            raise HTTPError(400)  # Unknown content-type.

        return True

    __copy__ = copy
    __repr__ = __str__


class HTTPRequest:
    def __init__(self, path: typing.Optional[str]=None,
                 host: typing.Optional[str]="",
                 method: typing.Optional[str]="GET",
                 http_version: typing.Optional[int]=None,
                 headers: typing.Optional[HTTPHeaders]=None,
                 cookies: typing.Optional[HTTPCookies]=None,
                 body: typing.Optional[HTTPBody]=None):
        self.stage = _REQUEST_EMPTY
        self.http_version = http_version or 10
        self._pending_bytes = b""
        self._splitted_pending_bytes = []
        self._splitted_bytes_length = 0
        self.path = path
        self.origin_path = None
        self.method = method
        self.host = host
        self.queries = MagicDict()
        self.cookies = cookies or HTTPCookies()
        self.headers = headers or HTTPHeaders()
        self.body = body or HTTPBody()
        self.body_expected = False

    def split_request(self):
        if len(self._pending_bytes) == 0:
            return
        if self._splitted_bytes_length > _MAX_HEADER_LENGTH + 1:
            return

        self._splitted_bytes_length += len(self._pending_bytes)
        self._splitted_pending_bytes.extend(
            self._pending_bytes.splitlines(keepends=True))
        if self._splitted_pending_bytes[-1][-1:] not in _CRLF_BYTES_MARK_LIST:
            self._pending_bytes = self._splitted_pending_bytes.pop(-1)
        else:
            self._pending_bytes = b""

        self._splitted_bytes_length -= len(self._pending_bytes)

    def parse_http_v1_request(self, request_bytes: bytes) -> bool:
        if self.stage in [_REQUEST_BROKEN, _REQUEST_DESTROYED,
                          _REQUEST_FINISHED]:
            raise HTTPError(500)
            # Should Not Send Content to Parse Request on this point.
        self._pending_bytes += request_bytes

        if self.stage == _REQUEST_EMPTY:
            self.stage = _REQUEST_WAITING_INITIAL

        if self.stage == _REQUEST_WAITING_INITIAL:
            self.split_request()
            if len(self._splitted_pending_bytes) == 0:
                if self._splitted_bytes_length > _MAX_HEADER_LENGTH:
                    self.stage = _REQUEST_BROKEN
                    raise HTTPError(413)  # 413 Request Entity Too Large
                return False  # Request Not Completed, wait.

            basic_info = _clear_crlf(
                self._splitted_pending_bytes.pop(0)).decode().split(" ")

            if len(basic_info) != 3:
                self.stage = _REQUEST_BROKEN
                raise HTTPError(400)  # 400 Bad Request

            self.method, self.origin_path, http_version = basic_info

            if http_version.lower() == "http/1.1":
                self.http_version = 11
            elif http_version.lower() == "http/1.0":
                self.http_version = 10
            else:
                self.stage = _REQUEST_BROKEN
                raise HTTPError(400)  # 400 Bad Request

            parsed_url = urllib.parse.urlparse(self.origin_path)
            self.path = parsed_url.path

            for query_name, query_value in urllib.parse.parse_qsl(
             parsed_url.query):
                self.queries.add(query_name, query_value)

            self.stage = _REQUEST_WAITING_HEADER

        if self.stage == _REQUEST_WAITING_HEADER:
            self.split_request()
            try:
                if self.headers.parse_http_v1_header(
                 self._splitted_pending_bytes) is False:
                    if self._splitted_bytes_length > _MAX_HEADER_LENGTH:
                        self.stage = _REQUEST_BROKEN
                        raise HTTPError(413)  # 413 Request Entity Too Large
                    return False  # Request Not Completed, wait.
            except HTTPError as e:
                raise e
            except:
                self.stage = _REQUEST_BROKEN
                raise HTTPError(400)  # 413 Bad Request

            if "host" in self.headers.keys():
                self.host = self.headers.pop("host")

            if "cookie" in self.headers:
                for cookie_header in self.headers.get_list("cookie"):
                    self.cookies.load(cookie_header)

            if self.method not in _SUPPORTED_METHODS:
                raise HTTPError(400)  # Bad Request

            if self.method in _BODY_EXPECTED_METHODS:
                self.body_expected = True
                content_length = int(self.headers.get_first("content-length"))
                if content_length > _MAX_BODY_LENGTH:
                    self.stage = _REQUEST_BROKEN
                    raise HTTPError(413)  # 413 Request Entity Too Large

                self.body.set_content_type(
                    self.headers.get_first("content-type"))
                self.body.set_content_length(content_length)

                self._pending_bytes = b"".join(
                    self._splitted_pending_bytes) + self._pending_bytes
                self._splitted_pending_bytes = []

                self.stage = _REQUEST_WAITING_BODY

        if self.stage == _REQUEST_WAITING_BODY:
            try:
                if self.body.parse_http_v1_body(self._pending_bytes) is False:
                    self._pending_bytes = b""
                    return False
            except HTTPError as e:
                raise e
            except:
                raise HTTPError(400)  # Unknown Error

        self._pending_bytes = b""
        self._splitted_pending_bytes = []
        self.stage = _REQUEST_FINISHED
        return True

    def make_http_v1_request(self):
        pass

    def __str__(self):
        return ("HTTPRequest("
                "method=%(method)s, "
                "path=%(path)s, "
                "http_version=%(http_version)s, "
                "host=%(host)s, "
                "headers=%(headers)s, "
                "cookies=%(cookies)s, "
                "queries=%(queries)s, "
                ")") % {
                    "method": repr(self.method),
                    "path": repr(self.path),
                    "http_version": repr(self.http_version),
                    "host": repr(self.host),
                    "headers": repr(self.headers),
                    "cookies": repr(self.cookies),
                    "queries": repr(self.queries)
                }

    __repr__ = __str__


class HTTPResponse:
    pass
