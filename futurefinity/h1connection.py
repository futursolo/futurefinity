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

from typing import Mapping, Optional, Callable, Any, Union, MutableMapping

from .utils import Identifier, cached_property
from . import log
from . import compat
from . import httpabc
from . import streams
from . import encoding
from . import httputils
from . import magicdict
from . import httpevents

from ._version import version as futurefinity_version

import abc
import sys
import enum
import asyncio
import inspect
import threading

_log = log.get_child_logger("h1connection")

_DEFAULT_MARK = Identifier()

_SELF_IDENTIFIER = "futurefinity/" + futurefinity_version


class CapitalizedH1Headers(dict):
    """
    Convert a string to HTTP Header style capitalized string.

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
            "content-disposition": "Content-Disposition",
            "if-unmodified-since": "If-Unmodified-Since",
            "proxy-authorization": "Proxy-Authorization",
        })
        self._mutex_lock = threading.Lock()

    def __getitem__(self, key: Text) -> Text:
        key = key.lower()

        if key not in self:
            with self._mutex_lock:
                self[key] = key.title()

        return dict.__getitem__(self, key)

capitalize_h1_header = CapitalizedH1Headers()


class _H1Request(httpabc.AbstractHTTPRequest):
    def __init__(
        self, *, method: compat.Text,
        uri: compat.Text, authority: Optional[compat.Text]=None,
        scheme: Optional[compat.Text]=None,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        self._method = method
        self._uri = uri
        self._headers = magicdict.TolerantMagicDict()

        if headers:
            self._headers.update(headers)

        if authority:
            self._headers["host"] = authority

        self._scheme = scheme

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._headers

    @property
    def method(self) -> compat.Text:
        return self._method

    @property
    def uri(self) -> compat.Text:
        return self._uri

    @property
    def authority(self) -> compat.Text:
        authority = self.headers.get("host", _DEFAULT_MARK)

        if authority is not _DEFAULT_MARK:
            return authority

        raise AttributeError("Authority(Host) is not set.")

    @property
    def scheme(self) -> compat.Text:
        """
        This is not mandatory in HTTP/1.1 since the scheme is not included
        in the request initial.
        """
        if self._scheme is None:
            raise AttributeError("Scheme is not set.")

        return self._scheme


class _H1Response(httpabc.AbstractHTTPResponse):
    def __init__(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        self._status_code = status_code
        self._headers = magicdict.TolerantMagicDict()

        if headers:
            self._headers.update(headers)

    @property
    def headers(self) -> Mapping[compat.Text, compat.Text]:
        return self._headers

    @property
    def status_code(self) -> int:
        return self._status_code


class H1Context(httpabc.AbstractHTTPContext):
    def __init__(
        self, is_client: bool, *, idle_timeout: int=10,
        max_initial_length: int=8 * 1024,  # 8K
        allow_keep_alive: bool=True,
        chunk_size: int=10 * 1024  # 10K
            ):
        self._is_client = is_client
        self._idle_timeout = idle_timeout
        self._max_initial_length = max_initial_length
        self._allow_keep_alive = allow_keep_alive
        self._chunk_size = chunk_size

    @property
    def is_client(self) -> bool:
        return self._is_client

    @property
    def idle_timeout(self) -> int:
        return self._idle_timeout

    @property
    def max_initial_length(self) -> int:
        return self._max_initial_length

    @property
    def allow_keep_alive(self) -> bool:
        return self._allow_keep_alive

    @property
    def chunk_size(self) -> int:
        return self._chunk_size


class _H1ConnnectionVariables:
    def __init__(self, tcp_stream: streams.AbstractStream):
        self._http_version = 11
        self._can_keep_alive = True

        self._tcp_stream = tcp_stream
        self._handled_stream_num = 0

    @property
    def http_version(self) -> int:
        return self._http_version

    @property
    def tcp_stream(self) -> Optional[streams.AbstractStream]:
        return self._tcp_stream

    @property
    def can_keep_alive(self) -> bool:
        return self._can_keep_alive

    @property
    def handled_stream_num(self) -> int:
        return self._handled_stream_num

    def disable_keep_alive(self):
        self._can_keep_alive = False

    def downgrade_http_version(self):
        self._http_version = 10
        self.disable_keep_alive()

    def inc_handled_stream_num(self):
        self._handled_stream_num += 1

    # def detach_stream(self):
    #     raise NotImplementedError


class _BaseH1InitialProcessor:
    def __init__(
            self, context: "H1Context", variables: _H1ConnnectionVariables):
        self._context = context
        self._variables = variables


class _H1BadInitialError(Exception):
    pass


class _H1InitialTooLargeError(Exception):
    pass


class _H1InitialParser(_BaseH1InitialProcessor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._read_len = 0
        self._line_separator = None
        self._parsed_basic_info_tuple = None
        self._parsed_headers = None
        self._parsed_initial = None

        self._exc = None

    @cached_property
    def parsed_initial(self) -> Union[_H1Request, _H1Response]:
        if self._parsed_initial is None:
            raise httpabc.InvalidHTTPOperationError(
                "The initial is not parsed properly.")

        return self._parsed_initial

    def _parse_http_version(self, http_version: compat.Text):
        http_version = http_version.strip().lower()
        if http_version == "http/1.1":
            pass  # nothing is going to happen.

        elif http_version == "http/1.0":
            self._variables.downgrade_http_version()

        else:
            raise ValueError("Unknown HTTP version.")

    async def _read_and_parse_basic_info(self):
        basic_info_line = await asyncio.wait_for(
            self._variables._tcp_stream.readuntil(b"\n", keep_separator=False),
            self.context.idle_timeout)

        basic_info_len = len(basic_info_line) + 1

        if basic_info_len > self._context.max_initial_length:
            raise _H1InitialTooLargeError(
                "The initial exceeded the initial limit.",
                total_length)

        self._read_len += basic_info_len

        if basic_info_line.endswith(b"\r"):
            # Remote is using CRLF.
            self._line_separator = b"\r\n"
            basic_info_line = basic_info_line[:-1]

        else:  # Remote is using LF.
            self._line_separator = b"\n"

        try:
            self._parsed_basic_info_tuple = encoding.ensure_str(
                basic_info_line, encoding="latin-1").split(" ", 2)
            # The basic info of a HTTP message uses latin-1 encoding.

        except Exception as e:
            raise _H1BadInitialError(
                "The basic info cannot be properly parsed.") from e

    async def _read_and_parse_headers(self):
        self._parsed_headers = magicdict.TolerantMagicDict()
        line_separator_len = len(self._line_separator)
        while True:
            header_line = await asyncio.wait_for(
                self._variables._tcp_stream.readuntil(
                    self._line_separator, keep_separator=False),
                self._context.idle_timeout)

            self._read_len += header_line + line_separator_length

            if not header_line:
                break  # Headers Completed.

            if self._read_len > self._context.max_initial_length:
                raise asyncio.LimitOverrunError(
                    "The intitial exceeded the initial limit.",
                    total_length)

            try:
                key, value = ensure_str(
                    header_line, encoding="latin-1").split(":", 1)
                # Headers of a HTTP message use latin-1 encoding.

            except Exception as e:
                raise H1BadMessageError(
                    "Headers cannot be properly parsed.") from e

            self._parsed_headers.add(key.strip(), value.strip())

        self._parsed_headers.freeze()

    def _parse_request(self):
        self._parse_http_version(
            self._parsed_basic_info_tuple[2])
        method = self._parsed_basic_info_tuple[0]
        uri = self._parsed_basic_info_tuple[1]

        self._parsed_initial = _H1Request(
            method=method, uri=uri, headers=self._parsed_headers)

    def _parse_response(self):
        self._parse_http_version(
            self._parsed_basic_info_tuple[0])
        try:
            status_code = int(self._parsed_basic_info_tuple[1])

        except Exception as e:
            raise _H1BadInitialError(
                "Unable to parse the status code.") from e

        self._parsed_initial = _H1Response(
            status_code=status_code, headers=self._parsed_headers)

    async def read_and_parse(self) -> Union[_H1Request, _H1Response]:
        if self._exc:
            raise self._exc

        if self._parsed_initial is not None:
            raise httpabc.InvalidHTTPOperationError(
                "The parser is not reusable.")

        try:
            await self._read_and_parse_basic_info()
            await self._read_and_parse_headers()

            if self._parsed_headers.get(
                    "connection", "close").lower().strip() != "keep-alive":
                self._variables.disable_keep_alive()

            if self.context.is_client:  # Client reads responses.
                self._parse_response()

            else:  # Server reads requests.
                self._parse_request()

            return self._parsed_initial

        except Exception as e:
            self._exc = e
            raise


class _H1InitialBuilder(_BaseH1InitialProcessor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._pending_data = []

        self._http_version = http_version

        self._justified_headers = None
        self._built_initial = None

        self._exc = None

    @cached_property
    def http_version(self) -> int:
        return self._http_version

    @cached_property
    def _http_version_str(self) -> int:
        if self.http_version == 11:
            return "HTTP/1.1"

        else:  # HTTP Version Cannot be something else than 10 or 11.
            return "HTTP/1.0"

    @cached_property
    def built_initial(self) -> Union[_H1Request, _H1Response]:
        if self._built_initial is None:
            raise httpabc.InvalidHTTPOperationError(
                "The initial is not built properly.")

        return self._built_initial

    def _build_request_basic_info(self, request: _H1Request):
        self._pending_data.append("{} {} {}\r\n".format(
            request.method, request.uri, self._http_version_str))

    def _build_response_basic_info(self, response: _H1Response):
        self._pending_data.append("{} {} {}\r\n".format(
            self._http_version_str,
            encoding.ensure_str(response.status_code),
            httputils.status_code_descriptions[status_code]))

    def _justify_request_headers(
            self, headers: Mapping[compat.Text, compat.Text]):
        assert self._justified_headers is None
        self._justified_headers = magicdict.TolerantMagicDict()
        self._justified_headers.update(headers)

        self._justified_headers.setdefault("accept", "*/*")
        self._justified_headers.setdefault("user-agent", _SELF_IDENTIFIER)

        if "connection" not in self._justified_headers.keys():
            if self._variables.can_keep_alive:
                self._justified_headers["connection"] = "Keep-Alive"

            else:
                self._justified_headers["connection"] = "Close"

    def _justify_response_headers(
            self, headers: Mapping[compat.Text, compat.Text]):
        assert self._justified_headers is None
        self._justified_headers = magicdict.TolerantMagicDict()
        self._justified_headers.update(headers)

        if status_code >= 400:
            self._justified_headers["connection"] = "Close"

        if "connection" not in self._justified_headers.keys():
            if self._variables.can_keep_alive:
                self._justified_headers["connection"] = "Keep-Alive"

            else:
                self._justified_headers["connection"] = "Close"

        self._justified_headers.setdefault("server", _SELF_IDENTIFIER)

        if "content-length" not in headers.keys():
            if self.http_version == 11:
                self._justified_headers.setdefault(
                    "transfer-encoding", "Chunked")
                # Auto Chunked Content Transfer is only enabled for responses.

    def _build_justified_headers(self):
        for key, value in self._justified_headers.items():
            self._pending_data.append(
                "{}: {}\r\n".format(capitalize_h1_header[key], value))

        self._justified_headers.freeze()

    def _write_pending_data(self):
        self._tcp_stream.write(encoding.ensure_bytes(
            "".join(self._pending_data), encoding="latin-1"))

    async def build_and_write(self, initial: Union[_H1Request, _H1Response]):
        if self._exc:
            raise self._exc

        if self._built_initial is not None:
            raise httpabc.InvalidHTTPOperationError(
                "The builder is not reusable.")

        if self.context.is_client:  # Client sends requests.
            assert isinstance(initial, _H1Request)

        else:  # Server sends responses.
            assert isinstance(initial, _H1Response)

        try:
            if self.context.is_client:  # Client sends requests.
                self._build_request_basic_info(initial)
                self._justify_request_headers(initial.headers)

            else:  # Server sends responses.
                self._build_response_basic_info(initial)
                self._justify_response_headers(initial.headers)

            if self._justified_headers.get(
                    "connection", "close").lower().strip() != "keep-alive":
                self._variables.disable_keep_alive()

            self._build_justified_headers()
            self._pending_data.append("\r\n")

            self._write_pending_data()
            await self._tcp_stream.drain()

            if self.context.is_client:
                self._built_initial = _H1Request(
                    method=initial.method, uri=initial.uri,
                    authority=getattr(initial, "authority", None),
                    scheme=getattr(initial, "scheme", None),
                    headers=self._justified_headers)

            else:  # Server-Side.
                self._built_initial = _H1Response(
                    status_code=initial.status_code,
                    headers=self._justified_headers)

        except Exception as e:
            self._exc = e
            raise


class _H1StreamWriter(httpabc.AbstractHTTPStreamWriter):
    def __init__(
        self, conn: "H1Connection",
            handler: httpabc.AbstractHTTPStreamHandler):
        self._conn = conn
        self._handler = handler

        self._variables.inc_handled_stream_num()
        self._stream_id = self._variables.handled_stream_num

        self._request = None
        self._response = None

        self._eof_read = False
        self._eof_written = False

        self._closed = False

    @property
    def http_version(self) -> int:
        return self._variables.http_version

    @property
    def stream_id(self) -> int:
        """
        A positive stream id means this is a stream over a connection.

        In HTTP/1.x, it keeps tracking the number of handled streams in
        current connection.
        """
        return self._stream_id

    @property
    def context(self) -> AbstractHTTPContext:
        return self._conn.context

    @property
    def _variables(self) -> _H1ConnnectionVariables:
        return self._conn._variables

    @cached_property
    def request(self) -> _H1Request:
        if self._request is None:
            raise AttributeError("Request is not Ready.")

        return self._request

    @cached_property
    def response(self) -> _H1Response:
        if self._response is None:
            raise AttributeError("Response is not Ready.")

        return self._response

    @cached_property
    def incoming(self) -> Union[_H1Request, _H1Response]:
        if self.context.is_client:
            return self.response

        else:
            return self.request

    @cached_property
    def outgoing(self) -> Union[_H1Request, _H1Response]:
        if self.context.is_client:
            return self.request

        else:
            return self.response

    async def send_response(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        assert not self.response_written, "You can only write response once."
        if not self.context.is_client:
            raise httpabc.InvalidHTTPOperationError(
                "An HTTP client cannot send responses to the remote.")

        try:
            response = _H1Response(
                status_code=status_code, headers=headers)

            builder = _H1InitialBuilder(
                context=self.context, variables=self._variables)
            await builder.build_and_write(response)

            self._response = builder.built_initial

        except:
            self.close()
            raise

    def response_written(self) -> bool:
        return self._response is not None

    async def _call_handler_with_event(self, event: httpabc.AbstractEvent):
        try:
            maybe_awaitable = self._handler.event_received(event)
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable

        except Excetion as e:
            self.close()

    async def _run_until_close(
        self, request: Optional[_H1Request]=None
            ) -> _ActionAfterStreamClosed:
        if self.context.is_client:
            assert request is not None

        else:
            assert request is None

        try:
            maybe_awaitable = self._handler.stream_created(self)
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable

            if self.closed():
                return

        except Excetion as e:
            self.close()

            try:
                maybe_awaitable = self._handler.stream_closed(e)
                if inspect.isawaitable(maybe_awaitable):
                    await maybe_awaitable

            except:
                _log.error(
                    "Error Occurred inside stream_closed.",
                    exc_info=sys.exc_info())

        if self.context.is_client:
            builder = _H1InitialBuilder(
                context=self.context, variables=self._variables)
            await builder.build_and_write(request)
            self._request = builder.built_initial

        parser = _H1InitialParser(
            context=self.context, variables=self._variables)
        incoming_initial = await parser.read_and_parse()

        if self.context.is_client:
            self._request = incoming_initial
            initial_event = httpevents.RequestReceived(self._request)

        else:
            self._response = incoming_initial
            initial_event = httpevents.ResponseReceived(self._response)

        await self._call_handler_with_event(initial_event)

        if self.closed():
            return

    @abc.abstractmethod
    def write(self, data: bytes):
        """
        Write the data.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def writelines(self, data: Iterable[bytes]):
        """
        Write a list (or any iterable) of data bytes.

        This is equivalent to call `AbstractStreamWriter.write` on each Element
        that the `Iterable` yields out, but in a more efficient way.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def drain(self):
        """
        Give the underlying implementation a chance to drain the pending data
        out of the internal buffer.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def can_write_eof(self) -> bool:
        """
        Return `True` if an eof can be written to the writer.
        """
        raise NotImplementedError

    def write_eof(self):
        """
        Write the eof.

        If the writer does not support eof(half-closed), it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def eof_written(self) -> bool:
        """
        Return `True` if the eof has been written or
        the writer has been closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def closed(self) -> bool:
        """
        Return `True` if the writer has been closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        """
        Close the writer.
        """
        """if not self._tcp_stream.is_closing():
            if not self._current_stream.at_eof():
                _log.warning(
                    "The body is not properly read, "
                    "tear down the connection.")
                self.close()
                self._tcp_stream.close()"""
        raise NotImplementedError

    @abc.abstractmethod
    async def wait_closed(self):
        """
        Wait the writer to close.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def abort(self):
        """
        Abort the writer without draining out all the pending buffer.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        """
        Return optional stream information.

        If The specific name is not presented and the default is not provided,
        the method should raise a `KeyError`.
        """
        raise NotImplementedError


class _H1ConnectionWriter(httpabc.AbstractHTTPStreamWriter):
    def __init__(self, conn: "H1Connection"):
        self._conn = conn

    @property
    def http_version(self) -> int:
        return self._conn.http_version

    @property
    def stream_id(self) -> int:
        """
        Stream id 0 means this is a connection.
        """
        return 0

    @property
    def context(self) -> AbstractHTTPContext:
        return self._conn.context

    @property
    def request(self) -> AbstractHTTPRequest:
        raise NotImplementedError("Stream 0 has no request.")

    @property
    def response(self) -> AbstractHTTPResponse:
        raise NotImplementedError("Stream 0 has no response.")

    @property
    def incoming(self) -> AbstractHTTPInitial:
        raise NotImplementedError("Stream 0 has no incoming initial.")

    @property
    def outgoing(self) -> AbstractHTTPInitial:
        raise NotImplementedError("Stream 0 has no outgoing initial.")

    async def send_response(
        self, *, status_code: int,
            headers: Optional[Mapping[compat.Text, compat.Text]]=None):
        raise NotImplementedError("You cannot send response from stream 0.")

    def response_written(self) -> bool:
        return False

    @abc.abstractmethod
    def write(self, data: bytes):
        raise NotImplementedError("You cannot write data from stream 0.")

    @abc.abstractmethod
    def writelines(self, data: Iterable[bytes]):
        raise NotImplementedError("You cannot write data from stream 0.")

    async def drain(self):
        if not self._conn._tcp_stream:
            return

        await self._conn._tcp_stream.drain()

    def can_write_eof(self) -> bool:
        return False

    def write_eof(self):
        raise NotImplementedError("You cannot write eof from stream 0.")

    def eof_written(self) -> bool:
        return False

    def closed(self) -> bool:
        return self._conn.closed()

    def close(self):
        self._conn.close()

    @abc.abstractmethod
    async def wait_closed(self):
        """
        Wait the writer to close.
        """
        raise NotImplementedError

    def abort(self):
        self._conn.abort()

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        if default is _DEFUALT_MARK:
            raise KeyError(name)

        return default

    def __end__(self):
        super().__end__()
        self.close()


class H1Connection(httpabc.AbstractHTTPConnection):
    def __init__(
        self, context: H1Context, tcp_stream: streams.AbstractStream,
        handler_factory: Callable[[], httpabc.AbstractHTTPStreamHandler], *,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        self._loop = loop or asyncio.get_event_loop()
        self._context = context

        self._handler_factory = handler_factory

        self._variables = _H1ConnnectionVariables(tcp_stream)

        self._running = False
        self._closed = False

        self._conn_handler = None
        self._current_http_stream = None

        self._send_request_fur = None
        self._handler_for_request_fur = None

    @property
    def http_version(self) -> int:
        return self._variables.http_version

    @property
    def context(self) -> H1Context:
        return self._context

    async def send_request(
        self, *, method: compat.Text,
        uri: compat.Text, authority: Optional[compat.Text]=None,
        headers: Optional[Mapping[compat.Text, compat.Text]]=None
            ) -> AbstractHTTPStreamHandler:
        """
        Send a request.

        This method is only usable on client side.
        """
        if not self.context.is_client:
            raise httpabc.InvalidHTTPOperationError(
                "An HTTP server cannot send requests to the remote.")

        assert self._running, "The connection is not being handled."

        if not self._variables.tcp_stream:
                raise httpabc.InvalidHTTPOperationError(
                    "The tcp stream has been "
                    "detached from the connection.")

        if self._variables._tcp_stream.closed():
            self.close()

        if self.closed():
            raise httpabc.InvalidHTTPOperationError(
                "The connection has been closed.")

        if self._current_http_stream is not None:
            raise RuntimeError(
                "HTTP/1.x can only have one stream per connection "
                "at the same time.")

        scheme = "http" if self._variables._tcp_stream.get_extra_info(
            "sslcontext", None) is None else "https"
        request = _H1Request(
            method=method, scheme=scheme, uri=uri, authority=authority,
            headers=headers)

        assert self._send_request_fur is not None and \
            not self._send_request_fur.done()

        self._send_request_fur.set_result(request)

        self._handler_for_request_fur = compat.create_future(self._loop)

        handler = await self._handler_for_request_fur

        return handler

    async def handle_until_close(self):
        assert not self._running, "The connection is being handled."

        try:
            if not self._tcp_stream:
                raise httpabc.InvalidHTTPOperationError(
                    "The tcp stream has been "
                    "detached from the connection.")

            if self._variables._tcp_stream.closed():
                self.close()

            if self.closed():
                raise httpabc.InvalidHTTPOperationError(
                    "The connection has been closed.")

            assert self._conn_handler is None
            assert self._send_request_fur is None
            assert self._current_http_stream is None

            self._conn_handler = self._handler_factory()

            self._conn_handler.stream_created(_H1ConnectionWriter(self))

            while True:
                handler = self._handler_factory()
                self._current_http_stream = _H1StreamWriter(
                    self, handler)

                if self.context.is_client:
                    self._send_request_fur = compat.create_future(self._loop)

                    request = await self._send_request_fur

                    if (self._handler_for_request_fur is not None and
                            not self._handler_for_request_fur.done()):
                        self._handler_for_request_fur.set_result(handler)

                    await self._current_http_stream._run_until_close(request)

                else:  # Server Side.
                    await self._current_http_stream._run_until_close()

                self._current_http_stream = None

                if not self._variables.can_keep_alive:
                    break

                if self._variables.tcp_stream:
                    if self._variables.tcp_stream.closed():
                        break

        finally:
            self._running = False
            self.close()

    def closed(self) -> bool:
        if self._variables.tcp_stream:
            if self._variables.tcp_stream.closed():
                self.close()

        return self._closed

    def _close_impl(self):
        if self._current_http_stream:
            self._current_http_stream.close()

        if self._conn_handler:
            self._conn_handler.stream_closed(None)

    def close(self):
        if self.closed():
            return

        self._closed = True

        self._close_impl()

    def abort(self):
        if self.closed():
            return

        self._closed = True

        if self._current_http_stream:
            self._current_http_stream.abort()

        self._close_impl()

    def __end__(self):
        super().__end__()
        self.close()
