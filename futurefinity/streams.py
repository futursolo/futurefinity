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

from .utils import Identifier
from . import compat

from typing import Iterable, Optional

import abc
import asyncio
import collections.abc

_DEFAULT_LIMIT = 2 ** 16
_DEFUALT_MARK = Identifier()


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


class AbstractStreamReader(collections.abc.AsyncIterator):
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


class AbstractStreamWriter:
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
    async def flush(self):
        """
        Give the underlying implementation a chance to flush the pending data
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
        Abort the writer without flush out all the pending buffer.
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
        if not self.__eof:
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
        """
        Return the length of the internal buffer.

        If the reader has no internal buffer, it should issue a
        `NotImplementedError`.
        """
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
        return (self.__buflen == 0) and self.__eof

    def has_eof(self) -> bool:
        return self.__eof

    async def wait_eof(self):
        """
        Wait for the eof has been appended.

        When limit(if any) has been reached, and the eof is not reached,
        this method will issue an `asyncio.LimitOverrunError`.
        """
        async with self.__read_lock:
            while True:
                try:
                    self.__try_raise_exc()

                except StreamEOFError:
                    return

                if self.__eof:
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
        self._write_impl(bytes(data))

    def writelines(self, data: Iterable[bytes]):
        self._write_impl(b"".join(data))

    def _write_eof_impl(self):
        """
        The implementation of write_eof.

        If the writer does not support eof(half-closed), it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    def write_eof(self):
        if self.__eof_written:
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
        if self.__closed:
            return

        self._close_impl()
        self.__closed = True

    async def wait_closed(self):
        """
        Wait the writer to close.

        This is the most compatible implementation.

        The subclasses should override it
        if more efficient implementation available.
        """
        if self._closed:
            return

        while True:
            await asyncio.sleep(.05)

            if self.closed():
                return

    def _abort_impl(self):
        """
        The default implementation of abort is the same as close a connection

        The subclass should override if abort can be implemented
        in a different way.
        """
        self.close()

    def abort(self):
        """
        Abort the writer without flush out all the pending buffer.
        """
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
