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

from .utils import Identifier, cached_property
from . import log
from . import compat

from typing import Iterable, Optional, Any, Callable

import abc
import enum
import asyncio
import collections
import collections.abc

_DEFAULT_LIMIT = 2 ** 16
_DEFUALT_MARK = Identifier()

_log = log.get_child_logger("streams")


class StreamEOFError(EOFError):
    """
    Read after `AbstractStreamReader.append_eof` has been called.
    """
    pass


class StreamClosedError(StreamEOFError, OSError):
    """
    Write after the stream is closed.
    """
    pass


class AbstractStreamReader(abc.ABC, collections.abc.AsyncIterator):
    """
    The abstract base class of the stream reader(read only stream).
    """
    def buflen(self) -> int:
        """
        Return the length of the internal buffer.

        If the reader has no internal buffer, it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def read(self, n: int=-1) -> bytes:
        """
        Read at most n bytes data.

        When at_eof() is True, the method will issue a `StreamEOFError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def readexactly(self, n: int=-1) -> bytes:
        """
        Read exactly n bytes data.

        If the eof reached before found the separator it will issue
        an `asyncio.IncompleteReadError`.

        When at_eof() is True, the method will issue a `StreamEOFError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def readuntil(
        self, separator: bytes=b"\n",
            *, keep_separator: bool=True) -> bytes:
        """
        Read until the separator has been found.

        When limit(if any) has been reached, and the separator is not found,
        this method will issue an `asyncio.LimitOverrunError`.
        Similarly, if the eof reached before found the separator it will issue
        an `asyncio.IncompleteReadError`.

        When at_eof() is True, the method will issue a `StreamEOFError`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def at_eof(self) -> bool:
        """
        Return True if eof has been appended and the internal buffer is empty.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def has_eof(self) -> bool:
        """
        Return True if eof has been appended.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def wait_eof(self):
        """
        Wait for the eof has been appended.

        When limit(if any) has been reached, and the eof is not reached,
        this method will issue an `asyncio.LimitOverrunError`.
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

    if compat.PY352:
        @abc.abstractmethod
        def __aiter__(self) -> "AbstractStreamReader":
            """
            The `AbstractStreamReader` is an `AsyncIterator`,
            so this function will simply return the reader itself.
            """
            raise NotImplementedError

    else:
        @abc.abstractmethod
        async def __aiter__(self) -> "AbstractStreamReader":
            """
            In Python 3.5.1 and before,
            `AsyncIterator.__aiter__` is a coroutine.
            """
            raise NotImplementedError

    @abc.abstractmethod
    async def __anext__(self) -> bytes:
        """
        Return the next line.

        This should be equivalent to`AbstractStreamReader.readuntil("\n")`
        """
        raise NotImplementedError


class AbstractStreamWriter(abc.ABC):
    """
    The abstract base class of the stream writer(write only stream).
    """
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


class AbstractStream(AbstractStreamReader, AbstractStreamWriter):
    """
    The abstract base class of the bidirectional stream(read and write stream).
    """
    pass


class BaseStreamReader(AbstractStreamReader):
    """
    This class can be used as long as the subclasses properly implemented
    `BaseStreamReader._fetch_data` method.
    """
    def __init__(
        self, *, limit: Optional[int]=_DEFAULT_LIMIT,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        assert isinstance(limit, Optional[int])
        self.__loop = loop or asyncio.get_event_loop()
        self.__limit = int(limit) if isinstance(limit, int) else None

        self.__buffer = collections.deque()
        self.__buflen = 0
        self.__eof = False

        self.__exc = None

        self.__read_lock = asyncio.Lock()

    @abc.abstractmethod
    async def _fetch_data(self) -> bytes:
        """
        Fetch data, the data will be appended to the internal buffer.

        If the EOF has been reached, it should issue an EOFError, so the
        reader will collect the eof and stop reading from it.

        This method must be overriden to support functionality of
        `BaseStreamReader`.

        For other exceptions, it will be treated as a normal exception, and
        will also append an EOF to the stream.
        """
        raise NotImplementedError

    def __try_raise_exc(self):
        if not self.has_eof():
            return

        if self.__exc is not None:
            raise self.__exc

        raise StreamEOFError

    def __pop_data_from_buffer(self) -> bytes:
        data = self.__buffer.popleft()
        self.__buflen -= len(data)

        return data

    def __pop_everything_from_buffer(self) -> bytes:
        data = b"".join(self.__buffer)
        self.__buflen = 0
        self.__buffer.clear()

        return data

    def __prepend_data_to_buffer(self, data: bytes):
        self.__buffer.appendleft(data)
        self.__buflen += len(data)

    def __append_data_to_buffer(self, data: bytes):
        self.__buffer.append(data)
        self.__buflen += len(data)

    async def __fetch_data_into_buffer(self):
        self.__try_raise_exc()
        try:
            data = await self._fetch_data()
            self.__append_data_to_buffer(data)

        except StreamEOFError:
            self.__eof = True

        except asyncio.CancelledError:
            raise

        except Exception as e:
            self.__eof = True
            self.__exc = e

    def buflen(self) -> int:
        return self.__buflen

    async def __read_impl(self, n: int=-1) -> bytes:
        assert n > 0
        self.__try_raise_exc()

        if not self.__buflen:
            await self.__fetch_data_into_buffer()

        if self.__buflen <= n:
            data = self.__pop_everything_from_buffer()
            return data

        else:
            buffer = []
            n_left = n

            while True:
                data = self.__pop_data_from_buffer()

                if len(data) > n_left:
                    data, data_rest = data[:n_left], data[n_left:]
                    self.__prepend_data_to_buffer(data_rest)

                buffer.append(data)
                n_left -= len(data)

                if n_left == 0:
                    break

            return b"".join(buffer)

    async def read(self, n: int=-1) -> bytes:
        async with self.__read_lock:
            self.__try_raise_exc()

            if n < 0:
                buffer = []

                try:
                    data = await self.__read_impl(
                        self.__limit or _DEFAULT_LIMIT)
                    buffer.append(data)

                except StreamEOFError:
                    return b"".join(buffer)

            elif n == 0:
                return b""

            else:
                return await self.__read_impl(n)

    async def readexactly(self, n: int=-1) -> bytes:
        if n < 0:
            raise ValueError("readexactly size can not be less than zero.")

        async with self.__read_lock:
            self.__try_raise_exc()

            if n == 0:
                return b""

            n_left = n
            buffer = []

            while True:
                try:
                    data = await self.__read_impl(n_left)

                except StreamEOFError as e:
                    raise asyncio.IncompleteReadError(
                        b"".join(buffer), n) from e

                n_left -= len(data)

                buffer.append(data)
                if n_left == 0:
                    break

            return b"".join(buffer)

    async def readuntil(
        self, separator: bytes=b"\n",
            *, keep_separator: bool=True) -> bytes:
        seplen = len(separator)
        if seplen == 0:
            raise ValueError("Separator should be at least one-byte string.")

        async with self.__read_lock:
            self.__try_raise_exc()

            buffer = bytearray()
            offset = 0

            while True:
                while len(buffer) - offset < seplen:
                    try:
                        buffer.extend(await self.__read_impl(
                            self.__limit or _DEFAULT_LIMIT))

                    except StreamEOFError:
                        raise asyncio.IncompleteReadError(bytes(buffer), None)

                seppos = buffer.find(separator, offset)
                if seppos != -1:
                    break

                offset = len(buffer) + 1 - seplen

                if self.__limit is not None:
                    if offset > self.__limit:
                        self.__prepend_data_to_buffer(bytes(buffer))
                        raise asyncio.LimitOverrunError(
                            "Separator is not found, "
                            "and the buffer exceeds the limit.", offset)

            if self.__limit is not None:
                if seppos > self.__limit:
                    raise asyncio.LimitOverrunError(
                        "Separator is found, but chunk is longer than limit.",
                        seppos)

            if keep_separator:
                data = buffer[:seppos + seplen]

            else:
                data = buffer[:seppos]

            self.__prepend_data_to_buffer(bytes(buffer[seppos + seplen:]))
            return bytes(data)

    def at_eof(self) -> bool:
        return (self.__buflen == 0) and self.has_eof()

    def has_eof(self) -> bool:
        return self.__eof

    async def wait_eof(self):
        async with self.__read_lock:
            while True:
                try:
                    self.__try_raise_exc()

                except StreamEOFError:
                    return

                if self.has_eof():
                    return

                if self.__limit is not None:
                    if self.__buflen > self.__limit:
                        raise asyncio.LimitOverrunError(
                            "EOF is not found, "
                            "but the buffer limit has been reached.")

                try:
                    await self.__fetch_data_into_buffer()

                except StreamEOFError:
                    return

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        if default is _DEFUALT_MARK:
            raise KeyError(name)

        return default

    if compat.PY352:
        def __aiter__(self) -> "BaseStreamReader":
            return self

    else:
        async def __aiter__(self) -> "BaseStreamReader":
            return self

    async def __anext__(self) -> bytes:
        try:
            data = await self.readuntil(b"\n")

        except StreamEOFError as e:
            raise StopAsyncIteration from e

        except asyncio.IncompleteReadError as e:
            return e.partial

        return data


class BaseStreamWriter(AbstractStreamWriter):
    """
    This class can be used as long as the subclasses properly implemented
    all the abstract methods in this class and `AbstractStreamWriter` that is
    not overriden in this class.
    """
    def __init__(self):
        self.__eof_written = False
        self.__closed = False

    @abc.abstractmethod
    def _write_impl(self, data: bytes):
        """
        Write the data. If the stream cannot be written any more,
        this should issue a `StreamClosedError` to prevent from
        further writing.
        """
        raise NotImplementedError

    def write(self, data: bytes):
        if self.eof_written():
            raise StreamEOFError("EOF written.")

        if self.closed():
            raise StreamClosedError

        self._write_impl(bytes(data))

    def writelines(self, data: Iterable[bytes]):
        if self.eof_written() or self.closed():
            raise StreamClosedError("Write after EOF or stream closed.")

        self._write_impl(b"".join(data))

    def _write_eof_impl(self):
        """
        The implementation of write_eof.

        If the writer does not support eof(half-closed), it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    def write_eof(self):
        if self.eof_written() or self.closed():
            return

        self._write_eof_impl()
        self.__eof_written = True

    def eof_written(self) -> bool:
        return self.__eof_written

    @abc.abstractmethod
    def _check_if_closed_impl(self) -> bool:
        raise NotImplementedError

    def closed(self) -> bool:
        if not self.__closed:
            self.__closed = self._check_if_closed_impl()

        return self.__closed

    @abc.abstractmethod
    def _close_impl(self):
        raise NotImplementedError

    def close(self):
        if self.closed():
            return

        self._close_impl()
        self.__closed = True

    async def wait_closed(self):
        """
        This is the most compatible implementation.

        The subclasses should override it
        if more efficient implementation is available.
        """
        if self._closed:
            return

        while True:
            await asyncio.sleep(.05)

            if self.closed():
                return

    def _abort_impl(self):
        """
        The default implementation of abort is the same as closing a stream.

        The subclass should override if abort can be implemented
        in a different way.
        """
        self.close()

    def abort(self):
        """
        Abort the writer without drain out all the pending buffer.
        """
        if self.closed():
            return

        self._abort_impl()
        self.__closed = True

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        if default is _DEFUALT_MARK:
            raise KeyError(name)

        return default


class BaseStream(AbstractStream, BaseStreamReader, BaseStreamWriter):
    """
    This class can be used as long as the subclasses satisfys
    the requirements of `BaseStreamReader` and `BaseStreamWriter`.
    """
    def __init__(
        self, *, limit: Optional[int]=_DEFAULT_LIMIT,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        super(BaseStreamReader, self).__init__(limit=limit, loop=loop)
        super(BaseStreamWriter, self).__init__()


class Stream(BaseStream):
    def __init__(
        self, transport: asyncio.Transport, protocol: "_StreamHelperProtocol",
        *, limit: int=_DEFAULT_LIMIT,
            loop: Optional[asyncio.AbstractEventLoop]=None):
        assert isinstance(limit, int) and limit > 0

        self._limit = limit
        self._loop = loop or asyncio.get_event_loop()
        self._transport = transport
        self._protocol = protocol

        super(BaseStream, self).__init__(limit=self._limit, loop=self._loop)

        self._wait_closed_lock = asyncio.Lock()

        self._wait_closed_fur = None

    @property
    def transport(self) -> asyncio.Transport:
        return self._transport

    async def _fetch_data(self) -> bytes:
        return await self._protocol._fetch_data_impl()

    def _write_impl(self, data: bytes):
        self.transport.write(data)

    def can_write_eof(self) -> bool:
        return self.transport.can_write_eof()

    def _write_eof_impl(self):
        self.transport.write_eof()

    async def drain(self):
        await self._protocol._drain_impl()

    @cached_property
    def _check_if_closed_impl(self) -> Callable[[], bool]:
        if compat.PY351:
            return self.transport.is_closing

        # Python 3.5.0 Compatibility Layer.
        if hasattr(self.transport, "is_closing"):
            return self.transport.is_closing

        if hasattr(self.transport, "_closing"):
            def check_fn():
                return self.transport._closing

            return check_fn

        if hasattr(self.transport, "_closed"):
            def check_fn():
                return self.transport._closed

            return check_fn

        else:
            raise NotImplementedError(
                "This method is not implemented for a transport that "
                "has no _closing or _closed attribute. "
                "Consider override this method to custom the check method.")

    def _close_impl(self):
        self.transport.close()

        if (self._wait_closed_fur is not None and
                not self._wait_closed_fur.done()):
            self._wait_closed_fur.set_result(None)

    async def wait_closed(self):
        """
        Wait the writer to close.

        This is the most compatible implementation.

        The subclasses should override it
        if more efficient implementation available.
        """
        async with self._wait_closed_lock:
            if self.closed():
                return

            while True:
                assert self._wait_closed_fur is None or \
                    self._wait_closed_fur.done()

                self._wait_closed_fur = self._loop.create_future()

                try:
                    done, pending = await asyncio.wait(
                        [
                            self._protocol._wait_closed_impl(),
                            self._wait_closed_fur
                        ], loop=self._loop,
                        return_when=asyncio.FIRST_COMPLETED)

                    for fur in pending:
                        fur.cancel()

                finally:
                    self._wait_closed_fur.cancel()

                await asyncio.sleep(0)  # Touch the event loop.
                if self.closed():
                    return

    def _abort_impl(self):
        self.transport.abort()

        if (self._wait_closed_fur is not None and
                not self._wait_closed_fur.done()):
            self._wait_closed_fur.set_result(None)

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        val = self.transport.get_extra_info(name, default)
        if val is _DEFUALT_MARK:
            raise KeyError(name)

        return val


class _StreamHelperProtocol(asyncio.Protocol):
    def __init__(
        self, fur: asyncio.Future, *, limit: int=_DEFAULT_LIMIT,
            loop: Optional[asyncio.BaseEventLoop]=None):
        self._loop = loop or asyncio.get_event_loop()
        self._limit = limit

        self._fur = fur

        self._stream = None

        self._allow_open_after_eof = True

        self._fetch_data_impl_lock = asyncio.Lock()
        self._drain_impl_lock = asyncio.Lock()
        self._wait_closed_impl_lock = asyncio.Lock()

        self._fetch_data_impl_fur = None
        self._drain_impl_fur = None
        self._wait_closed_impl_fur = None

        self._pending_buffer = []

        self._writing_paused = False
        self._eof_received = False
        self._closed = False

        self._exc = None

    def connection_made(self, transport: asyncio.Transport):
        self._stream = Stream(
            transport=transport, protocol=self, limit=self._limit,
            loop=self._loop)

        self._allow_open_after_eof = transport.get_extra_info(
            "sslcontext") is not None

        if not self._fur.done():
            return self._fur.set_result(self._stream)

        else:
            self._stream.close()

    def resume_writing(self):
        self._writing_paused = False

        if (self._drain_impl_fur is not None and
                not self._drain_impl_fur.done()):
            self._drain_impl_fur.set_result(None)

    def pause_writing(self):
        self._writing_paused = True

    def data_received(self, data: bytes):
        self._pending_buffer.append(data)

        if (self._fetch_data_impl_fur is not None and
                not self._fetch_data_impl_fur.done()):
            self._fetch_data_impl_fur.set_result(None)

    def eof_received(self) -> bool:
        self._eof_received = True

        if (self._fetch_data_impl_fur is not None and
                not self._fetch_data_impl_fur.done()):
            self._fetch_data_impl_fur.set_result(None)

        return self._allow_open_after_eof

    def connection_lost(self, exc: BaseException):
        self._eof_received = True
        self._closed = True

        if (self._fetch_data_impl_fur is not None and
                not self._fetch_data_impl_fur.done()):
            self._fetch_data_impl_fur.set_result(None)

        if (self._drain_impl_fur is not None and
                not self._drain_impl_fur.done()):
            self._drain_impl_fur.set_result(None)

        if (self._wait_closed_impl_fur is not None and
                not self._wait_closed_impl_fur.done()):
            self._wait_closed_impl_fur.set_result(None)

    async def _fetch_data_impl(self) -> bytes:
        async with self._fetch_data_impl_lock:
            while True:
                if self._pending_buffer:
                    data = b"".join(self._pending_buffer)
                    self._pending_buffer.clear()

                    return data

                if self._eof_received or self._closed:
                    if self._exc:
                        raise self._exc

                    raise StreamEOFError

                assert self._fetch_data_impl_fur is None or \
                    self._fetch_data_impl_fur.done()

                self._fetch_data_impl_fur = self._loop.create_future()

                try:
                    await self._fetch_data_impl_fur

                finally:
                    self._fetch_data_impl_fur.cancel()

    async def _drain_impl(self) -> bytes:
        async with self._drain_impl_lock:
            while True:
                if not self._writing_paused:
                    return

                if self._closed:
                    return

                assert self._drain_impl_fur is None or \
                    self._drain_impl_fur.done()

                self._drain_impl_fur = self._loop.create_future()

                try:
                    await self._fetch_data_impl_fur

                finally:
                    self._fetch_data_impl_fur.cancel()

    async def _wait_closed_impl(self) -> bytes:
        async with self._wait_closed_impl_lock:
            while True:
                if self._closed:
                    return

                assert self._wait_closed_impl_fur is None or \
                    self._wait_closed_impl_fur.done()

                self._wait_closed_impl_fur = self._loop.create_future()

                try:
                    await self._wait_closed_impl_fur

                finally:
                    self._wait_closed_impl_fur.cancel()


async def open_connection(
    host: Optional[compat.Text]=None, port: Optional[int]=None, *,
    loop: Optional[asyncio.AbstractEventLoop]=None,
        limit: int=_DEFAULT_LIMIT, **kwargs) -> Stream:
    assert isinstance(limit, int) and limit > 0

    loop = loop or asyncio.get_event_loop()
    fur = compat.create_future(loop=loop)

    def factory():
        return _StreamHelperProtocol(fur=fur, limit=limit, loop=loop)

    await loop.create_connection(factory, host, port, **kwargs)

    return await fur


async def start_server(
    callback: Callable[[Stream], Optional[compat.Awaitable[None]]],
    host: Optional[compat.Text]=None, port: Optional[int]=None, *,
    loop: Optional[asyncio.AbstractEventLoop]=None,
        limit: int=_DEFAULT_LIMIT, **kwargs) -> asyncio.AbstractServer:
    assert isinstance(limit, int) and limit > 0

    loop = loop or asyncio.get_event_loop()

    def after_connected(fur: asyncio.Future):
        if fur.cancelled():
            return

        stream = fur.result()
        result = callback(stream)

        if iscoroutine(result):
            compat.ensure_future(result, loop=loop)

    def factory():
        fur = compat.create_future(loop=loop)  # asyncio.Future
        fur.add_done_callback(after_connected)
        return _StreamHelperProtocol(fur=fur, limit=limit, loop=loop)

    return await loop.create_server(factory, host, port, **kwds)
