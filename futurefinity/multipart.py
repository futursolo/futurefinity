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

from typing import Optional, Mapping, Tuple

from . import compat
from . import encoding
from . import protocol
from . import security
from . import magicdict

_CRLF_BYTES_MARK = b"\r\n"


class HTTPMultipartFileField:
    """
    Containing a file as a http form field.
    """
    def __init__(self, fieldname: compat.Text, filename: compat.Text,
                 content: bytes,
                 content_type: compat.Text="application/octet-stream",
                 headers: Optional[Mapping[compat.Text, compat.Text]]=None,
                 encoding: compat.Text="binary"):
        self.fieldname = fieldname
        self.filename = filename
        self.content = content
        self.content_type = content_type
        self.headers = headers or protocol.HTTPHeaders()
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
        raise NotImplementedError("HTTPMultipartFileField is not copyable.")

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
            raise RuntimeError("Unknown content-type.")

        for field in content_type.split(";"):  # Search Boundary
            if field.find("boundary=") == -1:
                continue
            boundary = encoding.ensure_bytes(field.split("=")[1])
            if boundary.startswith(b'"') and boundary.endswith(b'"'):
                boundary = boundary[1:-1]
            break
        else:
            raise RuntimeError("Cannot Find Boundary.")
        full_boundary = b"--" + boundary
        body_content = data.split(full_boundary + b"--")[0]

        full_boundary += _CRLF_BYTES_MARK
        splitted_body_content = body_content.split(full_boundary)

        for part in splitted_body_content:
            if not part:
                continue

            initial, content = part.split(_CRLF_BYTES_MARK * 2)
            headers = protocol.HTTPHeaders.parse(initial)

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
                raise RuntimeError("Cannot Parse Body.")
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
                raise RuntimeError("Unknown Field Type")

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
        raise NotImplementedError("HTTPMultipartBody is not copyable.")

    __copy__ = copy
