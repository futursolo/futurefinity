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

import asyncio
import collections.abc

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
    @property
    def buflen(self) -> int:
        """
        Return the length of the internal buffer.

        If the reader has no internal buffer, it should issue a
        `NotImplementedError`.
        """
        raise NotImplementedError

    async def read(self, n: int=-1) -> bytes:
        """
        Read at most n bytes data.

        When at_eof() is True, the method will issue a `StreamEOFError`.
        """
        raise NotImplementedError

    async def readexactly(self, n: int=-1) -> bytes:
        raise NotImplementedError

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

    def at_eof(self) -> bool:
        """
        Return True if eof has been appended and the internal buffer is empty.
        """
        raise NotImplementedError

    def has_eof(self) -> bool:
        """
        Return True if eof has been appended.
        """
        raise NotImplementedError

    async def wait_eof(self):
        """
        Wait for the eof has been appended.

        When limit(if any) has been reached, and the eof is not reached,
        this method will issue an `asyncio.LimitOverrunError`.
        """
        raise NotImplementedError

    def get_extra_info(
            self, name: compat.Text, default: Any=_DEFUALT_MARK) -> Any:
        """
        Return optional stream information.

        If The specific name is not presented and the default is not provided,
        the method should raise a `KeyError`.
        """
        raise NotImplementedError

    if compat.PY352:
        def __aiter__(self) -> "AbstractStreamReader":
            """
            The `AbstractStreamReader` is an `AsyncIterator`,
            so this function will simply return the reader itself.
            """
            raise NotImplementedError

    else:
        async def __aiter__(self) -> "AbstractStreamReader":
            """
            In Python 3.5.1 and before,
            `AsyncIterator.__aiter__` is a coroutine.
            """
            raise NotImplementedError

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
    def write(self, data: bytes):
        """
        Write the data.
        """
        raise NotImplementedError

    def writelines(self, data: Iterable[bytes]):
        """
        Write a list (or any iterable) of data bytes.

        This is equivalent to call `AbstractStreamWriter.write` on each Element
        that the `Iterable` yields out, but in a more efficient way.
        """
        raise NotImplementedError

    async def flush(self):
        """
        Give the underlying implementation a chance to flush the pending data
        out of the internal buffer.
        """
        raise NotImplementedError

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

    def eof_written(self) -> bool:
        """
        Return `True` if the eof has been written or
        the writer has been closed.
        """
        raise NotImplementedError

    def closed(self) -> bool:
        """
        Return `True` if the writer has been closed.
        """
        raise NotImplementedError

    def close(self):
        """
        Close the writer.
        """
        raise NotImplementedError

    async def wait_closed(self):
        """
        Wait the writer to close.
        """
        raise NotImplementedError

    def abort(self):
        """
        Abort the writer without flush out all the pending buffer.
        """
        raise NotImplementedError

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
