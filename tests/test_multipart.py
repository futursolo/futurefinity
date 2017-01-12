#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2017 Futur Solo
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

import futurefinity

import io
import os
import cgi
import pytest


class HTTPMultipartTestCase:
    def test_multipart_file_field_init(self):
        file_content = os.urandom(100)
        file_field = futurefinity.multipart.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        assert file_field.fieldname == "test-field"
        assert file_field.filename == "test.file"

        assert file_field.content == file_content
        assert file_field.content_type == "image/png"

        assert isinstance(
            file_field.headers, futurefinity.magicdict.TolerantMagicDict)

        assert file_field.encoding == "binary"

    def test_multipart_file_field_string_method(self):
        file_content = os.urandom(100)
        file_field = futurefinity.multipart.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )
        assert str(file_field) == (
            "HTTPMultipartFileField(filename='test.file', "
            "content_type='image/png', "
            "headers=TolerantMagicDict([]), "
            "encoding='binary')")

    def test_multipart_file_field_assemble(self):
        file_content = os.urandom(100)
        file_field = futurefinity.multipart.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        assembled_bytes = file_field.assemble()
        initial, content = assembled_bytes.split(b"\r\n\r\n", 1)
        headers = futurefinity.httputils.parse_headers(initial + b"\r\n")

        assert file_content == content[:-2]
        assert headers["content-type"] == "image/png"
        assert headers["content-transfer-encoding"] == "binary"
        assert headers["content-disposition"] == (
            "form-data; name=\"test-field\"; filename=\"test.file\"")

    def test_multipart_file_field_copy(self):
        file_content = os.urandom(100)
        file_field = futurefinity.multipart.HTTPMultipartFileField(
            fieldname="test-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        with pytest.raises(NotImplementedError):
            file_field.copy()

    def test_multipart_body_init(self):
        body = futurefinity.multipart.HTTPMultipartBody(a="b")

        assert "a" in body.keys()
        assert body["a"] == "b"

    def test_multipart_body_parse(self):
        file_content = os.urandom(100)
        body_bytes = b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; \
name=\"normal-field\"\r\n"
        body_bytes += b"\r\n"
        body_bytes += b"hello\r\n"
        body_bytes += b"-------as7B98bFk\r\n"
        body_bytes += b"Content-Disposition: form-data; name=\"file-field\"; \
filename=\"test.txt\"\r\n"
        body_bytes += b"Content-Type: application/octet-stream\r\n"
        body_bytes += b"Content-Transfer-Encoding: binary\r\n"
        body_bytes += b"\r\n"
        body_bytes += file_content + b"\r\n"
        body_bytes += b"-------as7B98bFk--\r\n"

        with pytest.raises(RuntimeError):
            futurefinity.multipart.HTTPMultipartBody.parse(
                "any/any; boundary=-----as7B98bFk", body_bytes)

        with pytest.raises(RuntimeError):
            futurefinity.multipart.HTTPMultipartBody.parse(
                "multipart/form-data", body_bytes)

        body = futurefinity.multipart.HTTPMultipartBody.parse(
            "multipart/form-data; boundary=\"-----as7B98bFk\"", body_bytes)

        assert "normal-field" in body.keys()
        assert body["normal-field"] == "hello"

        assert "file-field" in body.files
        assert body.files["file-field"].content == file_content

    def test_multipart_body_assemble(self):
        file_content = os.urandom(100)

        file_field = futurefinity.multipart.HTTPMultipartFileField(
            fieldname="file-field", filename="test.file",
            content=file_content,
            content_type="image/png",
            headers=None,
            encoding="binary"
        )

        body = futurefinity.multipart.HTTPMultipartBody()
        body.files.add("file-field", file_field)
        body.add("normal-field", "hello")

        body_bytes, content_type = body.assemble()

        parsed_body = cgi.FieldStorage(fp=io.BytesIO(body_bytes), environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(body_bytes))
        })

        assert parsed_body.getvalue("normal-field") == "hello"
        assert parsed_body.getvalue("file-field") == file_content

    def test_multipart_body_str_method(self):
        body = futurefinity.multipart.HTTPMultipartBody()
        assert isinstance(str(body), str)

    def test_multipart_body_repr_method(self):
        body = futurefinity.multipart.HTTPMultipartBody()
        assert isinstance(repr(body), str)

    def test_multipart_body_copy(self):
        body = futurefinity.multipart.HTTPMultipartBody()

        with pytest.raises(NotImplementedError):
            body.copy()
