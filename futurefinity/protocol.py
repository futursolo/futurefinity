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


from futurefinity.utils import (ensure_str, ensure_bytes, format_timestamp,
                                MagicDict, TolerantMagicDict)

from http.cookies import SimpleCookie as HTTPCookies
from http.client import responses as status_code_text

import futurefinity

import io
import uuid
import typing

import urllib.parse

__all__ = ["status_code_text", "HTTPCookies"]

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


def _split_initial_lines(content: typing.Union[str, bytes],
                         reply_times: int=1,
                         max_split: int=-1) -> typing.Union[str, bytes]:
    if isinstance(content, str):
        return content.split(_CRLF_MARK * reply_times, max_split)
    if isinstance(content, bytes):
        return content.split(_CRLF_BYTES_MARK * reply_times, max_split)


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


class CapitalizedHTTPv1Header(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.update({
            "date": "Date",
            "etag": "ETag",
            "allow": "Allow",
            "cookie": "Cookie",
            "server": "Server",
            "connection": "Connection",
            "keep-alive": "Keep-Alive",
            "set-cookie": "Set-Cookie",
            "user-agent": "User-Agent",
            "content-md5": "Content-MD5",
            "content-type": "Content-Type",
            "content-range": "Content-Range",
            "if-none-match": "If-None-Match",
            "last-modified": "Last-Modified",
            "content-length": "Content-Length",
            "content-encoding": "Content-Encoding",
        })

    def __getitem__(self, key: str) -> str:
        if key in self:
            return dict.__getitem__(self, key)

        self[key] = key.title()
        return self[key]


capitalize_header = CapitalizedHTTPv1Header()


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

            header = ensure_str(splitted_data.pop(0))

            if header in _CRLF_MARK_LIST:
                return True

            header = _clear_crlf(header)
            (key, value) = header.split(":", 1)
            self.add(key.strip(), value.strip())

        else:
            raise HTTPError(413)  # Too many Headers.

        return False

    def accept_cookies_for_request(self, cookies: HTTPCookies):
        cookie_string = ""
        if "cookie" in self.keys():
            cookie_string += self["cookie"]
        for cookie_name, cookie_morsel in cookies.items():
            cookie_string += "%(cookie_name)s=%(cookie_value)s; " % {
                "cookie_name": cookie_name,
                "cookie_value": cookie_morsel.value
            }
        if cookie_string:
            self["cookie"] = cookie_string

    def accept_cookies_for_response(self, cookies: HTTPCookies):
        for cookie_morsel in cookies.values():
            self.add("set-cookie", cookie_morsel.OutputString())

    def make_http_v1_header(self) -> bytes:
        header_bytes = b""
        for (header_name, header_value) in self.items():
            header_bytes += ensure_bytes(
                "%(header_name)s: %(header_value)s" % {
                    "header_name": capitalize_header[header_name],
                    "header_value": header_value
                }) + _CRLF_BYTES_MARK

        return header_bytes

    __copy__ = copy
    __repr__ = __str__


class HTTPFile:
    def __init__(self, fieldname: str, filename: str,
                 content: typing.Union[str, bytes],
                 content_type: str="application/octet-stream",
                 headers: typing.Optional[HTTPHeaders]=None,
                 encoding: str="binary"):
        self.fieldname = fieldname
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

    def make_http_v1_form_field(self) -> bytes:
        field = b""
        headers = self.headers.copy()

        headers["content-type"] = self.content_type
        headers["content-transfer-encoding"] = self.encoding

        content_disposition = "form-data; "
        content_disposition += "name=\"%s\"; " % self.fieldname
        content_disposition += "filename=\"%s\"" % self.filename
        headers["content-disposition"] = content_disposition

        field += headers.make_http_v1_header()
        field += _CRLF_BYTES_MARK
        field += ensure_bytes(self.content)
        field += _CRLF_BYTES_MARK

        return field


class HTTPBody(TolerantMagicDict):
    def __init__(self, *args, **kwargs):
        TolerantMagicDict.__init__(self, *args, **kwargs)
        self._content_length = 0
        self._content_type = kwargs.get(
            "content_type", "application/x-www-form-urlencoded")
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
                self.add(ensure_str(key), ensure_str(value))

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
                        fieldname=disposition_dict.get_first("name", ""),
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

    def make_http_v1_body(self):
        body = b""
        if self._content_type == "application/x-www-form-urlencoded":
            body += ensure_bytes(urllib.parse.urlencode(self))

        if self._content_type.lower().startswith("multipart/form-data"):
            boundary = "----------FutureFinityFormBoundary" + str(
                uuid.uuid4()).upper()
            self.set_content_type(
                "multipart/formdata; boundary=" + boundary)

            full_boundary = b"--" + boundary.encode()

            for field_name, field_value in self.items():
                body += full_boundary + _CRLF_BYTES_MARK

                if isinstance(field_value, str):
                    body += b"Content-Disposition: form-data; "
                    body += ensure_bytes("name=\"%s\"\r\n" % field_name)
                    body += _CRLF_BYTES_MARK

                    body += ensure_bytes(field_value)
                    body += _CRLF_BYTES_MARK

                elif isinstance(field_value, HTTPFile):
                    body += field_value.make_http_v1_form_field()

                else:
                    raise HTTPError(400)  # Unknown Field Type.

            body += full_boundary + b"--" + _CRLF_BYTES_MARK

        else:
            raise HTTPError(400)  # Unknown POST Content Type.

        self.set_content_length(len(body))
        return body

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
        self.http_version = http_version or 10
        self._pending_bytes = b""
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

    def parse_http_v1_request(self, request_bytes: bytes) -> (bool, bytes):
        self._pending_bytes += request_bytes

        if self._pending_bytes.find(_CRLF_BYTES_MARK * 2) == -1:
            if len(self._pending_bytes) > _MAX_HEADER_LENGTH:
                raise HTTPError(413)  # 413 Request Entity Too Large
            return (False, b"")  # Request Not Completed, wait.

        request_initial, request_body = _split_initial_lines(
            self._pending_bytes, reply_times=2, max_split=1)

        origin_headers = _split_initial_lines(ensure_str(request_initial))

        basic_info = ensure_str(origin_headers.pop(0)).split(" ")

        if len(basic_info) != 3:
            raise HTTPError(400)  # 400 Bad Request

        self.method, self.origin_path, http_version = basic_info

        if http_version.lower() == "http/1.1":
            self.http_version = 11
        elif http_version.lower() == "http/1.0":
            self.http_version = 10
        else:
            raise HTTPError(400)  # 400 Bad Request

        parsed_url = urllib.parse.urlparse(self.origin_path)
        self.path = parsed_url.path

        for query_name, query_value in urllib.parse.parse_qsl(
         parsed_url.query):
            self.queries.add(query_name, query_value)

        try:
            self.headers.parse_http_v1_header(origin_headers)
        except HTTPError as e:
            raise e
        except:
            raise HTTPError(400)  # 400 Bad Request

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
                raise HTTPError(413)  # 413 Request Entity Too Large

            self.body.set_content_type(
                self.headers.get_first("content-type"))
            self.body.set_content_length(content_length)

        self._pending_bytes = b""
        return (True, request_body)

    def make_http_v1_request(self):
        request = b""

        if self.method not in _SUPPORTED_METHODS:
            raise HTTPError(400)  # Unknown HTTP method

        request += ensure_bytes(self.method) + b" "
        parse_result = urllib.parse.urlparse(self.path)
        if parse_result.netloc and not self.host:
            self.host = parse_result.netloc

        encoded_queries = urllib.parse.urlencode(self.queries)
        if parse_result.query:
            if encoded_queries:
                encoded_queries += "&"
            encoded_queries += parse_result.query

        url = urllib.parse.urlunparse(urllib.parse.ParseResult(
            scheme="", netloc="", path=parse_result.path,
            params="", query=encoded_queries, fragment=""))

        request += ensure_bytes(url) + b" "

        if self.http_version == 11:
            request += b"HTTP/1.1"
        elif self.http_version == 10:
            request += b"HTTP/1.1"
        else:
            raise HTTPError(400)  # Unknown HTTP Version

        request += _CRLF_BYTES_MARK

        headers = self.headers.copy()

        headers.accept_cookies_for_request(self.cookies)

        body = b""
        if self.method in _BODY_EXPECTED_METHODS:
            self.body_expected = True
            if isinstance(self.body, HTTPBody):
                body += self.body.make_http_v1_body()

                headers["content-length"] = self.body.get_content_length()

                headers["content-type"] = self.body.get_content_type()

            elif isinstance(self.body, bytes):
                body = self.body

        request += headers.make_http_v1_header()

        request += _CRLF_BYTES_MARK

        request += body

        return request

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
    def __init__(self,
                 http_version: typing.Optional[int]=None,
                 status_code: typing.Optional[int]=None,
                 headers: typing.Optional[HTTPHeaders]=None,
                 cookies: typing.Optional[HTTPCookies]=None,
                 body: typing.Optional[bytes]=None):
        self.http_version = http_version or 10
        self.status_code = status_code or 200

        self.headers = headers or HTTPHeaders()
        self.cookies = cookies or HTTPCookies()
        self.body = body or b""

        self._pending_bytes = b""

    def make_http_v1_response(self):
        response = b""
        if self.http_version == 11:
            response += b"HTTP/1.1 "
        elif self.http_version == 10:
            response += b"HTTP/1.1 "
        else:
            raise HTTPError(500)  # Unknown HTTP Version

        response += ensure_bytes(str(self.status_code)) + b" "
        response += ensure_bytes(status_code_text[self.status_code])
        response += _CRLF_BYTES_MARK

        headers = self.headers.copy()

        if "content-type" not in headers.keys():
            headers.add("content-type", "text/html; charset=utf-8;")

        if "content-length" not in headers.keys():
            headers.add("content-length",
                        str(len(self.body)))

        if "date" not in headers.keys():
            headers.add("date", format_timestamp())

        headers.accept_cookies_for_response(self.cookies)

        response += headers.make_http_v1_header()
        response += _CRLF_BYTES_MARK

        response += self.body

        return response

    def parse_http_v1_response(self, response_bytes) -> (bool, bytes):
        self._pending_bytes += response_bytes

        if self._pending_bytes.find(_CRLF_BYTES_MARK * 2) == -1:
            if len(self._pending_bytes) > _MAX_HEADER_LENGTH:
                raise HTTPError(500)  # Server Response Header Too Large.

            return (False, b"")  # Response Not Completed, Wait.

        response_initial, response_body = _split_initial_lines(
            self._pending_bytes, reply_times=2, max_split=1)

        origin_headers = _split_initial_lines(ensure_str(response_initial))

        basic_info = origin_headers.pop(0).split(" ")

        http_version = basic_info[0]
        if http_version.lower() == "http/1.1":
            self.http_version = 11
        elif http_version.lower() == "http/1.0":
            self.http_version = 10
        else:
            raise HTTPError(500)  # 500 Initial Server Error

        try:
            self.status_code = int(basic_info[1])
        except:
            raise HTTPError(500)  # 500 Initial Server Error

        try:
            self.headers.parse_http_v1_header(origin_headers)
        except HTTPError as e:
            raise e
        except:
            raise HTTPError(500)  # 500 Initial Server Error

        if "set-cookie" in self.headers:
            for cookie_header in self.headers.get_list("set-cookie"):
                cookie_attrs = cookie_header.split(";")

                cookie_name, cookie_value = cookie_attrs.pop(
                    0).strip().split("=")
                cookie_name = cookie_name.strip()
                cookie_value = cookie_value.strip()

                if cookie_value.startswith(
                 "\"") and cookie_value.endswith("\""):
                    cookie_value = value[1:-1]

                self.cookies[cookie_name] = cookie_value

                for attr in cookie_attrs:
                    if attr.strip().lower() == "httponly":
                        self.cookies[cookie_name]["httponly"] = True
                        continue

                    if attr.strip().lower() == "secure":
                        self.cookies[cookie_name]["secure"] = True
                        continue

                    if attr.strip().lower().startswith("path"):
                        self.cookies[cookie_name]["path"] = attr.split(
                            "=")[1].strip()
                        continue

                    if attr.strip().lower().startswith("expires"):
                        self.cookies[cookie_name]["expires"] = attr.split(
                            "=")[1].strip()
                        continue

                    if attr.strip().lower().startswith("max-age"):
                        self.cookies[cookie_name]["max-age"] = int(attr.split(
                            "=")[1].strip())
                        continue

                    if attr.strip().lower().startswith("domain"):
                        self.cookies[cookie_name]["domain"] = attr.split(
                            "=")[1].strip()

        self._pending_bytes = b""
        return (True, response_body)
