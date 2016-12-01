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
``futurefinity.protocol`` contains the implementation of HTTP Protocol from
both client side and server side.

"""

from . import log
from . import compat
from . import encoding
from . import security
from . import httputils
from . import magicdict
from ._version import version as futurefinity_version

from collections import namedtuple
from typing import Union, Optional, Any, List, Mapping, Tuple

import sys
import json
import string
import traceback
import urllib.parse


_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_MAX_INITIAL_LENGTH = 8 * 1024  # 8K
_MAX_BODY_LENGTH = 52428800  # 50M

_CONN_INIT = object()

_CONN_INITIAL_WAITING = object()
_CONN_INITIAL_PARSED = object()

_CONN_STREAMED = object()

_CONN_BODY_WAITING = object()
_CONN_MESSAGE_PARSED = object()

_CONN_INITIAL_WRITTEN = object()
_CONN_BODY_WRITTEN = object()

_CONN_CLOSED = object()

protocol_log = log.get_child_logger("protocol")


class ProtocolError(Exception):
    """
    FutureFinity Protocol Error.

    All Errors from the Protocol are based on this class.
    """
    pass


class CapitalizedHTTPv1Headers(dict):
    """
    Convert a string to HTTPHeader style capitalize.

    .. code-block:: python3

      >>> capitalize_header = CapitalizedHTTPv1Header()
      >>> capitalize_header["set-cookie"]
      'Set-Cookie'
      >>> capitalize_header["SET-COOKIE"]
      'Set-Cookie'
      >>> capitalize_header["sET-CooKIe"]
      'Set-Cookie'
      >>> capitalize_header["MY-cUsToM-heAdER"]
      'My-Custom-Header'
    """
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.update({
            "te": "TE",
            "age": "Age",
            "date": "Date",
            "etag": "ETag",
            "from": "From",
            "host": "Host",
            "vary": "Vary",
            "allow": "Allow",
            "range": "Range",
            "accept": "Accept",
            "cookie": "Cookie",
            "expect": "Expect",
            "server": "Server",
            "referer": "Referer",
            "if-match": "If-Match",
            "if-range": "If-Range",
            "location": "Location",
            "connection": "Connection",
            "keep-alive": "Keep-Alive",
            "set-cookie": "Set-Cookie",
            "user-agent": "User-Agent",
            "content-md5": "Content-MD5",
            "retry-after": "Retry-After",
            "content-type": "Content-Type",
            "max-forwards": "Max-Forwards",
            "accept-ranges": "Accept-Ranges",
            "authorization": "Authorization",
            "content-range": "Content-Range",
            "if-none-match": "If-None-Match",
            "last-modified": "Last-Modified",
            "accept-charset": "Accept-Charset",
            "content-length": "Content-Length",
            "accept-encoding": "Accept-Encoding",
            "accept-language": "Accept-Language",
            "content-encoding": "Content-Encoding",
            "www-authenticate": "WWW-Authenticate",
            "if-modified-since": "If-Modified-Since",
            "proxy-authenticate": "Proxy-Authenticate",
            "if-unmodified-since": "If-Unmodified-Since",
            "proxy-authorization": "Proxy-Authorization",
        })

    def __getitem__(self, key: compat.Text) -> compat.Text:
        if key not in self:
            self[key] = key.title()

        return dict.__getitem__(self, key)


_capitalize_header = CapitalizedHTTPv1Headers()


class HTTPHeaders(magicdict.TolerantMagicDict):
    """
    HTTPHeaders class, based on TolerantMagicDict.

    It has not only all the features from TolerantMagicDict, but also
    can parse and make HTTP Headers.
    """
    def __str__(self) -> compat.Text:
        content_list = [(key, value) for (key, value) in self.items()]
        return "HTTPHeaders({})".format(str(content_list))

    def copy(self) -> "HTTPHeaders":
        return HTTPHeaders(self)

    @staticmethod
    def parse(data: Union[compat.Text, bytes, list,
                          magicdict.TolerantMagicDict]) -> "HTTPHeaders":
        headers = HTTPHeaders()
        headers.load_headers(data)
        return headers

    def assemble(self) -> bytes:
        """
        Assemble a HTTPHeaders Class to HTTP/1.x Form.
        """
        headers_str = ""
        for (name, value) in self.items():
            headers_str += "{}: {}".format(_capitalize_header[name], value)
            headers_str += _CRLF_MARK

        return encoding.ensure_bytes(headers_str)

    def load_headers(
        self, data: Union[compat.Text, bytes, list,
                          magicdict.TolerantMagicDict]):
        """
        Load HTTP Headers from another object.

        It will raise an Error if the header is invalid.
        """

        # For dict-like object.
        if hasattr(data, "items"):
            for (key, value) in data.items():
                self.add(key.strip(), value.strip())
            return

        if isinstance(data, (str, bytes)):
            # For string-like object.
            splitted_data = encoding.ensure_str(data).split(_CRLF_MARK)

            for header in splitted_data:
                if not header:
                    continue
                (key, value) = header.split(":", 1)
                self.add(key.strip(), value.strip())
            return

        # For list-like object.
        if hasattr(data, "__iter__"):
            for (key, value) in data:
                self.add(key.strip(), value.strip())
            return

        raise ValueError("Unknown Type of input data.")

    def accept_cookies_for_request(self, cookies: httputils.HTTPCookies):
        """
        Insert all the cookies as a request cookie header.
        """
        cookie_string = ""
        if "cookie" in self.keys():
            cookie_string += self["cookie"]
        for cookie_name, cookie_morsel in cookies.items():
            cookie_string += "{}={}; ".format(cookie_name, cookie_morsel.value)

        if cookie_string:
            self["cookie"] = cookie_string

    def accept_cookies_for_response(self, cookies: httputils.HTTPCookies):
        """
        Insert all the cookies as response set cookie headers.
        """
        for cookie_morsel in cookies.values():
            self.add("set-cookie", cookie_morsel.OutputString())

    __copy__ = copy
    __repr__ = __str__


class HTTPMultipartFileField:
    """
    Containing a file as a http form field.
    """
    def __init__(self, fieldname: compat.Text, filename: compat.Text,
                 content: bytes,
                 content_type: compat.Text="application/octet-stream",
                 headers: Optional[HTTPHeaders]=None,
                 encoding: compat.Text="binary"):
        self.fieldname = fieldname
        self.filename = filename
        self.content = content
        self.content_type = content_type
        self.headers = headers or HTTPHeaders()
        self.encoding = encoding

    def __str__(self) -> compat.Text:
        return ("HTTPMultipartFileField(filename={filename}, "
                "content_type={content_type}, "
                "headers={headers}, "
                "encoding={encoding})").format(
                    filename=repr(self.filename),
                    content_type=repr(self.content_type),
                    headers=repr(self.headers),
                    encoding=repr(self.encoding)
                )

    def assemble(self) -> bytes:
        """
        Convert this form field to bytes.
        """
        self.headers["content-type"] = self.content_type
        self.headers["content-transfer-encoding"] = self.encoding

        content_disposition = "form-data; "
        content_disposition += "name=\"{}\"; ".format(self.fieldname)
        content_disposition += "filename=\"{}\"".format(self.filename)
        self.headers["content-disposition"] = content_disposition

        field = self.headers.assemble()
        field += _CRLF_BYTES_MARK
        field += encoding.ensure_bytes(self.content)
        field += _CRLF_BYTES_MARK

        return field

    def copy(self) -> "HTTPMultipartFileField":
        raise ProtocolError("HTTPMultipartFileField is not copyable.")

    __copy__ = copy


class HTTPMultipartBody(magicdict.TolerantMagicDict):
    """
    HTTPBody class, based on TolerantMagicDict.

    It has not only all the features from TolerantMagicDict, but also
    can parse and make HTTP Body.
    """
    def __init__(self, *args, **kwargs):
        self.files = magicdict.TolerantMagicDict()
        magicdict.TolerantMagicDict.__init__(self, *args, **kwargs)

    @staticmethod
    def parse(content_type: compat.Text, data: bytes) -> "HTTPMultipartBody":
        """
        Parse HTTP v1 Multipart Body.

        It will raise an Error during the parse period if parse failed.
        """
        body_args = HTTPMultipartBody()
        if not content_type.lower().startswith("multipart/form-data"):
            raise ProtocolError("Unknown content-type.")

        for field in content_type.split(";"):  # Search Boundary
            if field.find("boundary=") == -1:
                continue
            boundary = encoding.ensure_bytes(field.split("=")[1])
            if boundary.startswith(b'"') and boundary.endswith(b'"'):
                boundary = boundary[1:-1]
            break
        else:
            raise ProtocolError("Cannot Find Boundary.")
        full_boundary = b"--" + boundary
        body_content = data.split(full_boundary + b"--")[0]

        full_boundary += _CRLF_BYTES_MARK
        splitted_body_content = body_content.split(full_boundary)

        for part in splitted_body_content:
            if not part:
                continue

            initial, content = part.split(_CRLF_BYTES_MARK * 2)
            headers = HTTPHeaders.parse(initial)

            disposition = headers.get_first("content-disposition")
            disposition_list = []
            disposition_dict = magicdict.TolerantMagicDict()

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
                raise ProtocolError("Cannot Parse Body.")
                # Mixed form-data will be supported later.
            content = content[:-2]  # Drop CRLF Mark

            if "filename" in disposition_dict.keys():
                body_args.files.add(
                    disposition_dict.get_first("name", ""),
                    HTTPMultipartFileField(
                        fieldname=disposition_dict.get_first("name", ""),
                        filename=disposition_dict.get_first("filename", ""),
                        content=content,
                        content_type=headers.get_first(
                            "content-type", "application/octet-stream"),
                        headers=headers,
                        encoding=headers.get_first("content-transfer-encoding",
                                                   "binary")))
            else:
                try:
                    content = content.decode()
                except UnicodeDecodeError:
                    pass
                body_args.add(disposition_dict.get_first("name", ""), content)

        return body_args

    def assemble(self) -> Tuple[bytes, compat.Text]:
        """
        Generate HTTP v1 Body to bytes.

        It will return the body in bytes and the content-type in str.
        """
        body = b""
        boundary = "----------FutureFinityFormBoundary"
        boundary += encoding.ensure_str(security.get_random_str(8)).lower()
        content_type = "multipart/form-data; boundary=" + boundary

        full_boundary = b"--" + encoding.ensure_bytes(boundary)

        for field_name, field_value in self.items():
            body += full_boundary + _CRLF_BYTES_MARK

            if isinstance(field_value, str):
                body += b"Content-Disposition: form-data; "
                body += encoding.ensure_bytes("name=\"{}\"\r\n".format(
                    field_name))
                body += _CRLF_BYTES_MARK

                body += encoding.ensure_bytes(field_value)
                body += _CRLF_BYTES_MARK
            else:
                raise ProtocolError("Unknown Field Type")

        for file_field in self.files.values():
            body += full_boundary + _CRLF_BYTES_MARK
            body += file_field.assemble()

        body += full_boundary + b"--" + _CRLF_BYTES_MARK
        return body, content_type

    def __str__(self) -> compat.Text:
        # Multipart Body is not printable.
        return object.__str__(self)

    def __repr__(self) -> compat.Text:
        # Multipart Body is not printable.
        return object.__repr__(self)

    def copy(self) -> "HTTPMultipartBody":
        raise ProtocolError("HTTPMultipartBody is not copyable.")

    __copy__ = copy


class HTTPIncomingMessage:
    """
    FutureFinity HTTP Incoming Message Class.

    This is the base class of `HTTPIncomingRequest` and `HTTPIncomingResponse`.
    """
    @property
    def _is_chunked_body(self) -> bool:
        """
        Return `True` if there is a chunked body in the message.
        """
        if not hasattr(self, "__is_chunked_body"):
            if self.http_version == 10:
                self.__is_chunked_body = False

            else:
                transfer_encoding = self.headers.get_first("transfer-encoding")

                if not transfer_encoding:
                    self.__is_chunked_body = False
                elif transfer_encoding.lower() == "chunked":
                    self.__is_chunked_body = True
                else:
                    self.__is_chunked_body = False

        return self.__is_chunked_body

    @property
    def scheme(self) -> compat.Text:
        """
        Return the scheme that the connection used.
        """
        if not hasattr(self, "_scheme"):
            if self.connection.use_tls:
                self._scheme = "https"
            else:
                self._scheme = "http"
        return self._scheme

    @property
    def _expected_content_length(self) -> int:
        """
        Return the expected content length of the message.
        """
        if not hasattr(self, "__expected_content_length"):
            content_length = self.headers.get_first("content-length")
            if not content_length:
                # No content length header found.
                self.__expected_content_length = -1
            elif not content_length.isdecimal():
                # Cannot convert content length to integer.
                self.__expected_content_length = -1

            else:
                self.__expected_content_length = int(content_length)

        return self.__expected_content_length

    @property
    def _body_expected(self) -> bool:
        """
        Return True if the body is expected.
        """
        if hasattr(self, "method"):
            if self.method.lower() == "head":
                return False
        if self._is_chunked_body:
            return True

        if isinstance(self, HTTPIncomingResponse):
            if self.headers.get_first("connection", "").lower() == "close":
                return True

        if self._expected_content_length != -1:
            return True
        return False


class HTTPIncomingRequest(HTTPIncomingMessage):
    """
    FutureFinity HTTP Incoming Request Class.

    This is a subclass of the `HTTPIncomingMessage`.

    This class represents a Incoming HTTP Request.
    """
    def __init__(self, method: compat.Text,
                 origin_path: compat.Text,
                 headers: HTTPHeaders,
                 connection: "HTTPv1Connection",
                 http_version: int=10,
                 body: Optional[bytes]=None):
        self.http_version = http_version
        self.method = method
        self.origin_path = origin_path
        self.headers = headers
        self.body = body
        self.connection = connection

    def _parse_origin_path(self):
        parsed_url = urllib.parse.urlparse(self.origin_path)

        self._path = parsed_url.path

        link_args = magicdict.TolerantMagicDict()
        for (query_name, query_value) in urllib.parse.parse_qsl(
         parsed_url.query):
            link_args.add(query_name, query_value)

        self._link_args = link_args

    @property
    def cookies(self) -> httputils.HTTPCookies:
        """
        Parse cookies and return cookies in a `httputils.HTTPCookies` instance.
        """
        if not hasattr(self, "_cookies"):
            cookies = httputils.HTTPCookies()
            if "cookie" in self.headers:
                for cookie_header in self.headers.get_list("cookie"):
                    cookies.load(cookie_header)
            self._cookies = cookies
        return self._cookies

    @property
    def path(self) -> compat.Text:
        """
        Parse path and return the path in `str`.
        """
        if not hasattr(self, "_path"):
            self._parse_origin_path()
        return self._path

    @property
    def host(self) -> compat.Text:
        """
        Parse host and return the host in `str`.
        """
        if not hasattr(self, "_host"):
            self._host = self.headers.get_first("host")
        return self._host

    @property
    def link_args(self) -> magicdict.TolerantMagicDict:
        """
        Parse link arguments and return link arguments in a
        `TolerantMagicDict` instance.
        """
        if not hasattr(self, "_link_args"):
            self._parse_origin_path()
        return self._link_args

    @property
    def body_args(self) -> Union[magicdict.TolerantMagicDict,
                                 HTTPMultipartBody,
                                 Mapping[Any, Any],
                                 List[Any]]:
        """
        Parse body arguments and return body arguments in a
        proper instance.
        """
        if not hasattr(self, "_body_args"):
            content_type = self.headers.get_first("content-type")

            if content_type.lower().strip() in (
             "application/x-www-form-urlencoded", "application/x-url-encoded"):
                self._body_args = magicdict.TolerantMagicDict(
                    urllib.parse.parse_qsl(
                        encoding.ensure_str(self.body),
                        keep_blank_values=True,
                        strict_parsing=True))

            elif content_type.lower().startswith(
             "multipart/form-data"):
                self._body_args = HTTPMultipartBody.parse(
                    content_type=content_type,
                    data=self.body)

            elif content_type.lower().strip() == "application/json":
                self._body_args = magicdict.TolerantMagicDict(
                    json.loads(encoding.ensure_str(self.body)))

            else:  # Unknown Content Type.
                raise ProtocolError("Unknown Body Type.")

        return self._body_args

    def __str__(self) -> compat.Text:
        return ("HTTPIncomingRequest("
                "method={method}, "
                "path={path}, "
                "http_version={http_version}, "
                "host={host}, "
                "headers={headers}, "
                "cookies={cookies}, "
                "link_args={link_args}, "
                ")").format(
                    method=repr(self.method),
                    path=repr(self.path),
                    http_version=repr(self.http_version),
                    host=repr(self.host),
                    headers=repr(self.headers),
                    cookies=repr(self.cookies),
                    link_args=repr(self.link_args))

    __repr__ = __str__


class HTTPIncomingResponse(HTTPIncomingMessage):
    """
    FutureFinity HTTP Incoming Response Class.

    This is a subclass of the `HTTPIncomingMessage`.

    This class represents a Incoming HTTP Response.
    """
    def __init__(self, status_code: int, http_version: int=10,
                 headers: Optional[HTTPHeaders]=None,
                 body: Optional[bytes]=None,
                 connection: Optional["HTTPv1Connection"]=None):
        self.http_version = http_version
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.connection = connection

    @property
    def cookies(self) -> httputils.HTTPCookies:
        """
        Parse cookies and return cookies in a `httputils.HTTPCookies` instance.
        """
        if not hasattr(self, "_cookies"):
            cookies = httputils.HTTPCookies()
            if "set-cookie" in self.headers:
                for cookie_header in self.headers.get_list("set-cookie"):
                    cookies.load(cookie_header)
            self._cookies = cookies
        return self._cookies

    def __str__(self) -> compat.Text:
        return ("HTTPIncomingResponse("
                "status_code={status_code}, "
                "http_version={http_version}, "
                "headers={headers}, "
                "cookies={cookies}, "
                ")").format(
                    status_code=repr(self.status_code),
                    http_version=repr(self.http_version),
                    headers=repr(self.headers),
                    cookies=repr(self.cookies))

    __repr__ = __str__


class BaseHTTPConnectionController:
    """
    FutureFinity Base HTTP Connection Controller Class.

    This is the model controller to the HTTP Connections.

    Any Connection Controllers should based on this class.
    """
    def __init__(self, *args, **kwargs):
        self.transport = None
        self.use_stream = False

    def initial_received(self, incoming: HTTPIncomingMessage):
        """
        Triggered when the initial of a message is received.
        """
        pass

    def stream_received(self, incoming: HTTPIncomingMessage, data: bytes):
        """
        Triggered when the stream of a message is received.

        This will only be triggered when the message is detected as
        a stream message.
        """
        raise NotImplementedError("You should override stream_received.")

    def error_received(self, incoming, exc: tuple):
        """
        Triggered when errors received when errors occurred during parsing
        the message.
        """
        raise NotImplementedError("You should override error_received.")

    def message_received(self, incoming: HTTPIncomingMessage):
        """
        Triggered when a message is completely received.

        This will not be triggered when the message is detected as
        a stream message.
        """
        raise NotImplementedError("You should override message_received.")

    def set_timeout_handler(self, suggested_time: Optional[int]=None):
        """
        Set a EventLoop.call_later instance, close transport after timeout.
        """
        pass

    def cancel_timeout_handler(self):
        """
        Cancel the EventLoop.call_later instance, prevent transport be closed
        accidently.
        """
        pass


class ConnectionParseError(ProtocolError, ConnectionError):
    """
    FutureFinity Connection Parse Error.

    Any Connection Parse Errors is based on this class.
    """
    pass


class ConnectionBadMessage(ConnectionParseError):
    """
    FutureFinity Connection Bad Message Error.

    This Error is raised when the message is not a valid message.
    """
    pass


class ConnectionEntityTooLarge(ConnectionParseError):
    """
    FutureFinity Connection Entity Too Large Error.

    This Error is raised when the message too large that FutureFinity cannot
    handle.
    """
    pass


class HTTPv1Connection:
    """
    FutureFinity HTTP v1 Connection Class.

    This class will control and parse the http v1 connection.
    """
    def __init__(self, controller: BaseHTTPConnectionController,
                 is_client: bool, http_version: int=10,
                 use_tls: bool=False,
                 sockname: Optional[Tuple[compat.Text, int]]=None,
                 peername: Optional[Tuple[compat.Text, int]]=None,
                 allow_keep_alive: bool=True):
        self.http_version = http_version
        self.is_client = is_client
        self.use_tls = use_tls
        self.sockname = sockname
        self.peername = peername

        self.controller = controller

        self.allow_keep_alive = allow_keep_alive

        self.max_initial_length = _MAX_INITIAL_LENGTH
        self.max_body_length = _MAX_BODY_LENGTH

        self._pending_bytes = bytearray()

        self._reset_connection()

    def _reset_connection(self):  # Reset Connection For Keep-Alive.
        self.controller.set_timeout_handler()

        self._use_keep_alive = None

        self._body_length = None
        self._next_chunk_length = None

        self._pending_body = b""

        self._parsed_incoming_info = {}
        self.incoming = None

        self._outgoing_chunked_body = False

        self.stage = _CONN_INIT

    @property
    def _can_keep_alive(self):
        if self.allow_keep_alive is False:
            return False
        if self.http_version == 10:
            return False

        if self._use_keep_alive is not None:
            return self._use_keep_alive
        return True

    def _parse_initial(self):
        initial_end = self._pending_bytes.find(_CRLF_BYTES_MARK * 2)

        if initial_end == -1:
            if len(self._pending_bytes) > self.max_initial_length:
                raise ConnectionEntityTooLarge(
                    "Initial Exceed its Maximum Length.")
            return

        initial_end += 2
        if initial_end > self.max_initial_length:
            raise ConnectionEntityTooLarge(
                "Initial Exceed its Maximum Length.")
            return

        pending_initial = encoding.ensure_bytes(
            self._pending_bytes[:initial_end])
        del self._pending_bytes[:initial_end + 2]

        basic_info, origin_headers = encoding.ensure_str(
            pending_initial).split(_CRLF_MARK, 1)

        basic_info = basic_info.split(" ")

        if self.is_client:
            http_version = basic_info[0]

            if not basic_info[1].isdecimal():
                raise ConnectionBadMessage("Bad Initial Received.")

            self._parsed_incoming_info["status_code"] = int(basic_info[1])

        else:
            if len(basic_info) != 3:
                raise ConnectionBadMessage("Bad Initial Received.")

            method, origin_path, http_version = basic_info

            self._parsed_incoming_info["method"] = basic_info[0]
            self._parsed_incoming_info["origin_path"] = basic_info[1]

        if http_version.lower() == "http/1.1":
            self.http_version = 11
        elif http_version.lower() == "http/1.0":
            self.http_version = 10
        else:
            raise ConnectionBadMessage("Unknown HTTP Version.")

        self._parsed_incoming_info["http_version"] = self.http_version

        try:
            headers = HTTPHeaders.parse(origin_headers)

        except Exception as e:
            raise ConnectionBadMessage("Bad Headers Received.") from e

        if self._can_keep_alive and "connection" in headers:
            self._use_keep_alive = headers.get_first(
                "connection").lower() == "keep-alive"

        self._parsed_incoming_info["headers"] = headers

        if self.is_client:
            try:
                self.incoming = HTTPIncomingResponse(
                    **self._parsed_incoming_info)
            except Exception as e:
                raise ConnectionBadMessage("Bad Initial Received.") from e

        else:
            try:
                self.incoming = HTTPIncomingRequest(
                    **self._parsed_incoming_info, connection=self)

            except Exception as e:
                raise ConnectionBadMessage("Bad Initial Received.") from e

        self.stage = _CONN_INITIAL_PARSED

    def _parse_next_chunk(self):
        if self._body_length is None:
            self._body_length = 0
        while True:
            if self._next_chunk_length is None:
                length_end = self._pending_bytes.find(_CRLF_BYTES_MARK)
                if length_end == -1:
                    if len(self._pending_bytes) > 10:
                        # FFFFFFFF\r\n is about 4GB, FutureFinity can only
                        # handle files less than 50MB by default.
                        raise ConnectionEntityTooLarge(
                            "The body is too large.")
                    return

                length_bytes = self._pending_bytes[:length_end]
                del self._pending_bytes[:length_end + 2]

                try:
                    self._next_chunk_length = int(length_bytes, 16)

                except ValueError as e:
                    # Not Valid Hexadecimal bytes
                    raise ConnectionBadMessage(
                        "Bad Chunk Length Received.") from e

                if self._next_chunk_length > self.max_body_length:
                    raise ConnectionEntityTooLarge(
                        "The body is too large.")

            if len(self._pending_bytes) < self._next_chunk_length + 2:
                return  # Data not enough.

            if self._next_chunk_length == 0:
                del self._pending_bytes[:2]
                self.incoming.body = self._pending_body
                self.stage = _CONN_MESSAGE_PARSED
                return  # Parse Finished.

            self._pending_body += self._pending_bytes[:self._next_chunk_length]
            del self._pending_bytes[:self._next_chunk_length + 2]
            self._body_length += self._next_chunk_length
            self._next_chunk_length = None

            if self._body_length > self.max_body_length:
                raise ConnectionEntityTooLarge(
                    "The body is too large.")

    def _parse_body(self):
        if self.incoming._is_chunked_body:
            self._parse_next_chunk()
            return

        if self._body_length is None:
            self._body_length = self.incoming._expected_content_length

        if self.is_client is True:
            if self._body_length == -1:
                return  # Waiting For Connection Close.

        if self._body_length > self.max_body_length:
            raise ConnectionEntityTooLarge("The body is too large.")

        if len(self._pending_bytes) < self._body_length:
            return  # Data not enough, waiting.

        self._pending_body = encoding.ensure_bytes(
            self._pending_bytes[:self._body_length])

        del self._pending_bytes[:self._body_length]

        self.incoming.body = self._pending_body
        self.stage = _CONN_MESSAGE_PARSED

    def data_received(self, data: bytes):
        """
        Trigger this function when data is received from the remote.
        """
        if not data:
            return  # Nothing received, nothing is going to happen.

        self._pending_bytes += data

        try:
            self._parse_incoming_message()
        except:
            if self.is_client:
                self._close_connection()

            else:
                self.stage = _CONN_MESSAGE_PARSED

            try:
                self.controller.error_received(self.incoming, sys.exc_info())

            except:
                protocol_log.exception(
                    "Error Occurred in error_received, "
                    "teardown the connection.")
                self._close_connection()

    def _parse_incoming_message(self):
        self.controller.cancel_timeout_handler()

        if self.is_client is False:
            if self.stage is _CONN_INIT:
                self.stage = _CONN_INITIAL_WAITING

        if self.stage is _CONN_INITIAL_WAITING:
            self._parse_initial()

        if self.stage is _CONN_INITIAL_PARSED:
            self.controller.initial_received(self.incoming)

            if self.controller.use_stream:
                self.stage = _CONN_STREAMED

            elif not self.incoming._body_expected:
                self.stage = _CONN_MESSAGE_PARSED

            else:
                self.stage = _CONN_BODY_WAITING
                if not self.incoming._is_chunked_body:
                    if (self.incoming._expected_content_length == -1 and
                       not self.is_client):
                        raise ConnectionBadMessage(
                            "Method Request a body, "
                            "but we cannot find a way to detect body length.")

        if self.stage is _CONN_STREAMED:
            self.controller.stream_received(
                self.incoming, encoding.ensure_bytes(self._pending_bytes))
            self._pending_bytes.clear()
            return

        if self.stage is _CONN_BODY_WAITING:
            self._parse_body()

        if self.stage is _CONN_MESSAGE_PARSED:
            self.controller.message_received(self.incoming)
            if self.is_client:
                if self._can_keep_alive:
                    self._reset_connection()
                else:
                    self._close_connection()
            return

    def write_initial(
        self, http_version: Optional[int]=None, method: compat.Text="GET",
            path: compat.Text="/", status_code: int=200,
            headers: Optional[HTTPHeaders]=None):
        """
        Write the initial to remote.
        """
        initial = b""

        if http_version is not None:
            self.http_version = http_version

        if self.http_version == 11:
            http_version_text = "HTTP/1.1"
        elif self.http_version == 10:
            http_version_text = "HTTP/1.0"
        else:
            raise ProtocolError("Unknown HTTP Version.")

        basic_info_template = "{} {} {}" + _CRLF_MARK
        if self.is_client:
            if self.stage is not _CONN_INIT:
                raise ProtocolError(
                    "Cannot write when connection stage is not _CONN_INIT.")

            basic_info = encoding.ensure_bytes(
                basic_info_template.format(method, path, http_version_text))

        else:
            if self.stage is not _CONN_MESSAGE_PARSED:
                raise ProtocolError("Unacceptable Function Access.")

            basic_info = encoding.ensure_bytes(basic_info_template.format(
                http_version_text, status_code,
                httputils.status_code_descriptions[status_code]))

        initial += basic_info

        if self._can_keep_alive and "connection" in headers:
            self._use_keep_alive = headers.get_first(
                "connection").lower() == "keep-alive"

        transfer_encoding = headers.get_first("transfer-encoding")
        if transfer_encoding is not None:
            if transfer_encoding.lower() == "chunked":
                self._outgoing_chunked_body = True
            else:
                self._outgoing_chunked_body = False
        else:
            self._outgoing_chunked_body = False

        if "connection" not in headers.keys():
            if self._can_keep_alive:
                headers["connection"] = "Keep-Alive"
            else:
                headers["connection"] = "Close"
        else:
            self._use_keep_alive = headers[
                "connection"].lower() == "keep-alive"

        if self.is_client:
            if "accept" not in headers.keys():
                headers["accept"] = "*/*"
            if "user-agent" not in headers.keys():
                headers["user-agent"] = "futurefinity/" + futurefinity_version
        else:
            if "server" not in headers.keys():
                headers["server"] = "futurefinity/" + futurefinity_version
            if method.lower() == "head":
                # For Head Request, there will not be a body.
                self._outgoing_chunked_body = False

        initial += headers.assemble()

        initial += _CRLF_BYTES_MARK

        self.controller.transport.write(initial)

        self.stage = _CONN_INITIAL_WRITTEN

    def write_body(self, body: bytes):
        """
        Write the body to remote.

        This can be triggered for many times. until `finish_writing`
        is triggered.
        """
        if self.stage not in (_CONN_INITIAL_WRITTEN, _CONN_BODY_WRITTEN):
            raise ProtocolError("Invalid Function Access.")
        self.stage = _CONN_BODY_WRITTEN
        if self._outgoing_chunked_body:
            self._write_body_chunk(body)
            return
        self.controller.transport.write(body)

    def _write_body_chunk(self, body_chunk: bytes):
        if not self._outgoing_chunked_body:
            raise ProtocolError("Invalid Function Access.")

        if not body_chunk:
            return
            # Prevent Body being finished accidentally.
            # Finish Body Writing by HTTPv1Connection.finish_writing

        chunk_bytes = b""

        body_chunk_length = len(body_chunk)
        chunk_bytes += encoding.ensure_bytes(
            hex(body_chunk_length)[2:].upper())
        chunk_bytes += _CRLF_BYTES_MARK

        chunk_bytes += body_chunk
        chunk_bytes += _CRLF_BYTES_MARK
        self.controller.transport.write(chunk_bytes)

    def finish_writing(self):
        """
        Trigger this function when everything is written.

        It will reset the connection or close it.
        """
        if self._outgoing_chunked_body:
            self.controller.transport.write(b"0" + _CRLF_BYTES_MARK * 2)

        if self.is_client:
            self.stage = _CONN_INITIAL_WAITING

        else:
            if self._can_keep_alive:
                self._reset_connection()
            else:
                self._close_connection()

    def connection_lost(
        self,
            exc: Tuple[Optional[Any], Optional[Any], Optional[Any]]=None):
        """
        Triggered when remote is closed.
        """
        if self.stage is _CONN_CLOSED:
            return  # This connection has been closed.

        if self.stage is _CONN_INIT:
            self.stage = _CONN_CLOSED
            return  # This connection has nothing, so nothing to cleanup.

        if self.is_client:
            if self.stage is _CONN_BODY_WAITING:
                self._pending_body = encoding.ensure_bytes(self._pending_bytes)

                self._pending_bytes.clear()

                self.incoming.body = self._pending_body
                self.stage = _CONN_MESSAGE_PARSED
                self._parse_incoming_message()  # Trigger Message Received.

        self._close_connection()

    def _close_connection(self):  # Close Connection.
        self.controller.cancel_timeout_handler()
        if self.controller.transport:
            self.controller.transport.close()

        self.stage = _CONN_CLOSED
