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
#
# This test is partially based on the following file:
# `https://github.com/python/asyncio/blob/master/tests/test_streams.py`

import futurefinity
import futurefinity.testutils

import os
import pytest
import socket
import asyncio
import tempfile

helper = futurefinity.testutils.TestHelper(__file__)


class _MockTransport(asyncio.Transport):
    def __init__(self):
        self._written_buffer = []
        self._eof_written = False
        self._closed = False
        self._aborted = False

        self._paused = False

    def write(self, data):
        self._written_buffer.append(data)

    def can_write_eof(self):
        return True

    def pause_reading(self):
        self._paused = True

    def resume_reading(self):
        self._paused = False

    def write_eof(self):
        self._eof_written = True

    def close(self):
        self._closed = True

    def abort(self):
        self._aborted = True

    def get_extra_info(self, name, default=None):
        return default


def _create_mocked_stream(*args, **kwargs):
    transport = _MockTransport()
    fur = asyncio.Future()

    protocol = futurefinity.streams._StreamHelperProtocol(
        fur=fur, *args, loop=helper.loop, **kwargs)

    protocol.connection_made(transport)

    return protocol, fur.result()


class StreamTestCase:
    DATA = b'line1\nline2\nline3\n'

    def test_create_stream(self):
        _create_mocked_stream()

    @helper.run_until_complete
    async def test_buflen(self):
        protocol, stream = _create_mocked_stream()
        assert stream.buflen() == 0

        protocol.data_received(os.urandom(5))

        await stream.read(1)
        assert stream.buflen() == 4

    @helper.run_until_complete
    async def test_read(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)

        assert await stream.read(100) == self.DATA

    @helper.run_until_complete
    async def test_read(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        assert await stream.read(100) == self.DATA

        with pytest.raises(futurefinity.streams.StreamEOFError):
            await stream.read(100)

    @helper.run_until_complete
    async def test_read_until_eof(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        assert await stream.read() == self.DATA

        with pytest.raises(futurefinity.streams.StreamEOFError):
            await stream.read(100)

    @helper.run_until_complete
    async def test_readexactly(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        assert await stream.readexactly(len(self.DATA)) == self.DATA

        with pytest.raises(asyncio.IncompleteReadError):
            await stream.readexactly(100)

    @helper.run_until_complete
    async def test_readuntil(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        assert await stream.readuntil(b"\n") == b"line1\n"
        assert await stream.readuntil(b"\n", keep_separator=False) == b"line2"
        assert await stream.readuntil(b"\n") == b"line3\n"

        with pytest.raises(asyncio.IncompleteReadError):
            await stream.readuntil(b"\n")

    @helper.run_until_complete
    async def test_readuntil_limit_overrun(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(os.urandom(100000).replace(b"\n\n", b"\r\r"))
        protocol.eof_received()

        with pytest.raises(futurefinity.streams.LimitOverrunError):
            await stream.readuntil(b"\n\n")

    @helper.run_until_complete
    async def test_at_eof(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        assert not stream.at_eof()
        await stream.read(1000)
        with pytest.raises(futurefinity.streams.StreamEOFError):
            await stream.read(1000)
        assert stream.at_eof()

    @helper.run_until_complete
    async def test_has_eof(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)

        assert not stream.has_eof()

        protocol.eof_received()

        await stream.read(1000)
        with pytest.raises(futurefinity.streams.StreamEOFError):
            await stream.read(1000)
        assert stream.has_eof()

    @helper.run_until_complete
    async def test_wait_eof(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(stream.wait_eof(), 0.1)

        protocol.eof_received()

        await stream.wait_eof()

    @helper.run_until_complete
    async def test_aiter(self):
        protocol, stream = _create_mocked_stream()

        protocol.data_received(self.DATA)
        protocol.eof_received()

        lines = []
        async for line in stream:
            lines.append(line)

        assert b"".join(lines) == self.DATA

    def test_write(self):
        protocol, stream = _create_mocked_stream()

        stream.write(self.DATA)
        stream.write_eof()
        with pytest.raises(futurefinity.streams.StreamEOFError):
            stream.write(self.DATA)

        assert b"".join(stream.transport._written_buffer) == self.DATA

    def test_writelines(self):
        protocol, stream = _create_mocked_stream()

        stream.write(self.DATA)
        stream.write_eof()
        with pytest.raises(futurefinity.streams.StreamEOFError):
            stream.writelines([b"line1\n", b"line2\n", b"line3\n"])

        assert b"".join(stream.transport._written_buffer) == self.DATA

    @helper.run_until_complete
    async def test_drain(self):
        protocol, stream = _create_mocked_stream()
        stream.write(self.DATA)
        await stream.drain()

        protocol.pause_writing()

        drain_fur = futurefinity.compat.ensure_future(stream.drain())

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(drain_fur), 0.1)

        protocol.resume_writing()
        await drain_fur

    def test_can_write_eof(self):
        protocol, stream = _create_mocked_stream()
        assert stream.can_write_eof() is True

    def test_write_eof(self):
        protocol, stream = _create_mocked_stream()

        stream.write_eof()
        assert stream.transport._eof_written is True

    def test_eof_written(self):
        protocol, stream = _create_mocked_stream()

        assert stream.eof_written() is False

        stream.write_eof()
        assert stream.eof_written() is True

    def test_close(self):
        protocol, stream = _create_mocked_stream()

        stream.close()

        assert stream.transport._closed is True

    def test_closed(self):
        protocol, stream = _create_mocked_stream()

        assert stream.closed() is False

        stream.close()
        assert stream.closed() is True

    @helper.run_until_complete
    async def test_wait_closed(self):
        protocol, stream = _create_mocked_stream()

        wait_closed_fur = futurefinity.compat.ensure_future(
            stream.wait_closed())

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(wait_closed_fur), 0.1)

        stream.close()

    @helper.run_until_complete
    async def test_base_writer_wait_closed(self):
        protocol, stream = _create_mocked_stream()

        wait_closed_fur = futurefinity.compat.ensure_future(
            futurefinity.streams.BaseStreamWriter.wait_closed(stream))

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(wait_closed_fur), 0.1)

        stream.close()

    def test_abort(self):
        protocol, stream = _create_mocked_stream()

        stream.abort()

        assert stream.transport._closed is False
        assert stream.transport._aborted is True


class TCPStreamServerTestCase:
    DATA = b'line1\nline2\nline3\n'

    @helper.run_until_complete
    async def test_start_server(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        done_fur = asyncio.Future(loop=helper.loop)

        async def remote_connected_callback(stream):
            try:
                stream.write(self.DATA)
                await stream.drain()
                assert await stream.read(1000) == self.DATA
                stream.close()

            except Exception as e:
                done_fur.set_exception(e)

            else:
                done_fur.set_result(None)

        await futurefinity.streams.start_server(
            remote_connected_callback, sock=sock, loop=helper.loop)

        host, port = sock.getsockname()

        reader, writer = await asyncio.open_connection(host=host, port=port)

        await asyncio.sleep(0)  # Reschedule the current task to the end.

        writer.write(self.DATA)
        await writer.drain()
        assert await reader.read(1000) == self.DATA

        await done_fur


class TCPStreamClientTestCase:
    DATA = b'line1\nline2\nline3\n'

    @helper.run_until_complete
    async def test_open_connection(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        done_fur = asyncio.Future(loop=helper.loop)

        async def remote_connected_callback(reader, writer):
            try:
                writer.write(self.DATA)
                await writer.drain()
                assert await reader.read(1000) == self.DATA
                writer.close()

            except Exception as e:
                done_fur.set_exception(e)

            else:
                done_fur.set_result(None)

        await asyncio.start_server(
            remote_connected_callback, sock=sock, loop=helper.loop)

        host, port = sock.getsockname()

        stream = await futurefinity.streams.open_connection(
            host=host, port=port)

        await asyncio.sleep(0)  # Reschedule the current task to the end.

        stream.write(self.DATA)
        await stream.drain()
        assert await stream.read(1000) == self.DATA

        await done_fur


@pytest.mark.skipunless("hasattr(socket, 'AF_UNIX')")
class UNIXStreamServerTestCase:
    DATA = b'line1\nline2\nline3\n'

    @helper.run_until_complete
    async def test_start_unix_server(self):
        done_fur = asyncio.Future(loop=helper.loop)

        async def remote_connected_callback(stream):
            try:
                stream.write(self.DATA)
                await stream.drain()
                assert await stream.read(1000) == self.DATA
                stream.close()

            except Exception as e:
                done_fur.set_exception(e)

            else:
                done_fur.set_result(None)

        with tempfile.NamedTemporaryFile() as f:
            path = f.name

        await futurefinity.streams.start_unix_server(
            remote_connected_callback, path, loop=helper.loop)

        reader, writer = await asyncio.open_unix_connection(path)

        await asyncio.sleep(0)  # Reschedule the current task to the end.

        writer.write(self.DATA)
        await writer.drain()
        assert await reader.read(1000) == self.DATA

        await done_fur


@pytest.mark.skipunless("hasattr(socket, 'AF_UNIX')")
class UNIXStreamClientTestCase:
    DATA = b'line1\nline2\nline3\n'

    @helper.run_until_complete
    async def test_open_unix_connection(self):
        done_fur = asyncio.Future(loop=helper.loop)

        async def remote_connected_callback(reader, writer):
            try:
                writer.write(self.DATA)
                await writer.drain()
                assert await reader.read(1000) == self.DATA
                writer.close()

            except Exception as e:
                done_fur.set_exception(e)

            else:
                done_fur.set_result(None)

        with tempfile.NamedTemporaryFile() as f:
            path = f.name

        await asyncio.start_unix_server(
            remote_connected_callback, path, loop=helper.loop)

        stream = await futurefinity.streams.open_unix_connection(path)

        await asyncio.sleep(0)  # Reschedule the current task to the end.

        stream.write(self.DATA)
        await stream.drain()
        assert await stream.read(1000) == self.DATA

        await done_fur
