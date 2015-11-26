#!/usr/bin/env python
#
# Copyright 2015 Futur Solo
#
# Licensed under the Apache License: Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing: software
# distributed under the License is distributed on an "AS IS" BASIS: WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND: either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
``futurefinity.utils`` contains a series of utilities that are useful to
dealing with HTTP Protocol.

This class is recommend to be imported without namespace.

.. code-block:: python3

  from futurefinity.utils import *

"""

import futurefinity
import urllib.parse
import functools
import collections
import collections.abc
import cgi
import io
import random
import string
import http.cookies
import time
import datetime
import email.utils
import calendar
import numbers
import typing
import os
import base64
import struct

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as AESCipher,
        algorithms as aes_algorithms,
        modes as aes_modes
    )
    from cryptography.hazmat.backends import default_backend as aes_backend
except ImportError:
    AESCipher = None
    aes_algorithms = None
    aes_modes = None
    aes_backend = None

MAX_HEADER_LENGTH = 4096

MAX_BODY_LENGTH = 52428800  # 50M

MULTIPART_BOUNDARY_HANDLERS = {}

SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PATCH", "PUT",
                     "OPTIONS", "CONNECT")
BODY_EXPECTED_METHODS = ("POST", "PATCH", "PUT")

_CRLF_MARK = "\r\n"
_CRLF_BYTES_MARK = b"\r\n"

_LF_MARK = "\n"
_LF_BYTES_MARK = b"\n"


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


def ensure_bytes(var: typing.Any) -> bytes:
    """
    Try to convert passed variable to a bytes object.
    """
    if isinstance(var, bytes):
        return var
    if var is None:
        return b""
    if not isinstance(var, str):
        strvar = str(var)
    else:
        strvar = var
    return strvar.encode()


def ensure_str(var: typing.Any) -> str:
    """
    Try to convert passed variable to a str object.
    """
    if isinstance(var, str):
        return var
    if var is None:
        return ""
    if isinstance(var, bytes):
        strvar = var.decode("utf-8")
    else:
        strvar = var
    return str(strvar)


class MagicDict(collections.abc.MutableMapping):
    """
    An implementation of one-to-many mapping.
    """
    def __init__(self, *args, **kwargs):
        self._dict = {}
        self._as_list = {}
        self._last_key = None
        if (len(args) == 1 and len(kwargs) == 0 and
                isinstance(args[0], HTTPHeaders)):
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            self.update(*args, **kwargs)

    def add(self, name, value):
        """
        Add a value to the MagicDict.
        """
        self._last_key = name
        if name in self:
            self._dict[name] = (ensure_str(self[name]) + ',' +
                                ensure_str(value))
            self._as_list[name].append(value)
        else:
            self[name] = value

    def get_list(self, name, default=None):
        """
        Return all values with the name in a list.
        """
        return self._as_list.get(name, default)

    def get_all(self):
        """
        Iter all values.
        """
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def get_first(self, name):
        """
        Get the first value with the name.
        """
        return self._as_list.get(name, [None])[0]

    def __setitem__(self, name, value):
        self._dict[name] = value
        self._as_list[name] = [value]

    def __getitem__(self, name):
        return self._dict[name]

    def __delitem__(self, name):
        del self._dict[name]
        del self._as_list[name]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def copy(self):
        """
        Create another instance of MagicDict but contains the same content.
        """
        return MagicDict(self)

    __copy__ = copy


class HTTPHeaders(MagicDict):
    """
    HTTPHeaders class, based on MagicDict. But Keys must be str and are
    case-insensitive.
    """
    def add(self, name: str, value: str):
        """
        Add a header and change the name to lowercase.
        """
        lower_name = name.lower()
        return MagicDict.add(self, lower_name, value)

    def get_list(self, name: str, default: typing.Optional[str]=None):
        """
        Get all header with the name in a list.
        """
        lower_name = name.lower()
        return MagicDict.get_list(self, lower_name, default=default)

    def __setitem__(self, name, value):
        lower_name = name.lower()
        return MagicDict.__setitem__(self, lower_name, value)

    def __getitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__getitem__(self, lower_name)

    def __delitem__(self, name):
        lower_name = name.lower()
        return MagicDict.__delitem__(self, lower_name)

    def copy(self):
        """
        Create another instance of HTTPHeaders but contains the same content.
        """
        return HTTPHeaders(self)

    __copy__ = copy


def render_template(template_name: str):
    """
    Decorator to render template gracefully.

    Only effective when nothing is written.

    Example:

    .. code-block:: python3

      @render_template("index.htm")
      async def get(self, *args, **kwargs):
          return {'content': 'Hello, World!!'}

    """
    def decorator(f):
        @functools.wraps(f)
        async def wrapper(self, *args, **kwargs):
            render_dict = await f(self, *args, **kwargs)
            if self._written:
                return
            return self.render_string(template_name, **render_dict)
        return wrapper
    return decorator


def decide_http_v1_mark(data: bytes) -> typing.Optional[bool]:
    """
    Decide the request is CRLF or LF.

    Return None if the request is still not finished.
    Return True if CRLF is used.
    Return False if LF is used.

    Raise an HTTPError(413) if Header is larger than _MAX_HEADER_LENGTH.
    """
    crlf_position = data.find(_CRLF_BYTES_MARK * 2)
    lf_position = data.find(_LF_BYTES_MARK * 2)
    if (crlf_position == -1 and lf_position == -1) and len(
       data) < _MAX_HEADER_LENGTH:
        return None  # Request Not Completed, wait.
    elif crlf_position != -1 and lf_position != -1:
        if lf_position > crlf_position:
            return True
        return False
    elif crlf_position != -1:
        return True
    elif lf_position != -1:
        return False
    else:
        raise HTTPError(413)  # 413 Request Entity Too Large


def split_data(data: typing.Union[str, bytes], use_crlf_mark: bool=True,
               mark_repeat: int=1, max_part: int=0) -> list:
    """
    Split data by CRLF, or LF.
    Raise an Error if data is not splittable.

    """
    spliter = _CRLF_BYTES_MARK
    if isinstance(data, bytes):
        if not use_crlf_mark:
            spliter = _LF_BYTES_MARK
    elif isinstance(data, str):
        if not use_crlf_mark:
            spliter = _LF_MARK
        else:
            spliter = _CRLF_MARK
    else:
        raise ValueError("%s type is not Splittable." % (type(data)))

    spliter = spliter * mark_repeat

    return data.split(spliter, max_part - 1)


def parse_http_v1_header(data: typing.Union[str, bytes],
                         use_crlf_mark: bool=True) -> HTTPHeaders:
    """
    Parse HTTP/1.x HTTP Header and return an HTTPHeader instance.
    """
    if isinstance(data, bytes):
        data = data.decode()
    parsed_headers = HTTPHeaders()
    for header in split_data(data, use_crlf_mark=use_crlf_mark):
        (key, value) = header.split(":", 1)
        parsed_headers.add(key.strip(), value.strip())

    return parsed_headers


def parse_http_v1_initial(data: bytes, use_crlf_mark: bool=True) -> tuple:
    """
    Parse HTTP/1.x Initial Part of Data.
    """
    initial = {
        "http_version": 10,
        "parsed_path": None,
        "parsed_queries": MagicDict(),
        "parsed_headers": None,
        "parsed_cookies": None
    }
    raw_initial, raw_body = split_data(data, use_crlf_mark=use_crlf_mark,
                                       mark_repeat=2, max_part=2)
    raw_initial = raw_initial.decode()

    basic_info, headers = split_data(raw_initial,
                                     use_crlf_mark=use_crlf_mark,
                                     max_part=2)

    basic_info = basic_info.split(" ")

    if len(basic_info) != 3:
        raise HTTPError(400)  # 400 Bad Request

    method, path, http_version = basic_info

    if http_version.lower() == "http/1.1":
        initial["http_version"] = 11
    elif http_version.lower() == "http/1.0":
        initial["http_version"] = 10
    else:
        raise HTTPError(400)  # 400 Bad Request

    initial["parsed_headers"] = parse_http_v1_header(
        headers, use_crlf_mark=use_crlf_mark)

    initial["parsed_headers"][":path"] = path
    initial["parsed_headers"][":method"] = method
    if "host" in initial["parsed_headers"].keys():
        initial["parsed_headers"][
            ":authority"] = initial["parsed_headers"].pop("host")

    if "cookie" in initial["parsed_headers"]:
        initial["parsed_cookies"] = http.cookies.SimpleCookie(
            initial["parsed_headers"].get("cookie"))
    else:
        initial["parsed_cookies"] = http.cookies.SimpleCookie()

    parsed_url = urllib.parse.urlparse(
        initial["parsed_headers"].get(":path"))

    initial["parsed_path"] = parsed_url.path

    for query in urllib.parse.parse_qsl(parsed_url.query):
        initial["parsed_queries"].add(query[0], query[1])

    if initial["parsed_headers"][":method"] in BODY_EXPECTED_METHODS:
        if int(initial["parsed_headers"].get_first(
         "content-length")) > MAX_BODY_LENGTH:
            raise HTTPError(413)  # 413 Request Entity Too Large

    return initial, raw_body


def parse_http_v1_body(data: bytes, content_length: typing.Union[str, int],
                       content_type: str, boundary=None) -> cgi.FieldStorage:
    """
    Parse HTTP/1.x Body.
    """
    return cgi.FieldStorage(fp=io.BytesIO(data), environ={
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": ensure_str(content_length)
    })


def security_secret_generator(length: int) -> str:
    """
    Generate a Security Secret securely with SystemGenerator.
    If SystemGenerator not available, use fake random generator as instead.
    """
    try:
        random_generator = random.SystemRandom()
    except:
        random_generator = random
    random_string = ""
    for i in range(0, length):
        random_string += random_generator.choice(
            string.ascii_letters + string.digits + string.punctuation)
    return random_string


def format_timestamp(ts: typing.Union[int, numbers.Real, tuple,
                                      time.struct_time,
                                      datetime.datetime]=None) -> str:
    """
    Make a timestamp that fits HTTP Response.
    """
    if not ts:
        ts = time.time()
    if isinstance(ts, numbers.Real):
        pass
    elif isinstance(ts, (tuple, time.struct_time)):
        ts = calendar.timegm(ts)
    elif isinstance(ts, datetime.datetime):
        ts = calendar.timegm(ts.utctimetuple())
    else:
        raise TypeError("unknown timestamp type: %r" % ts)
    return ensure_str(email.utils.formatdate(ts, usegmt=True))


def create_signed_str(secret: str, text: str) -> str:
    iv = os.urandom(16)

    content = struct.pack("l", int(time.time())) + ensure_bytes(text)

    hash = hmac.new(iv + ensure_bytes(secret), digestmod=hashlib.sha256)
    hash.update(ensure_bytes(content))
    signature = hash.digest()

    final_signed_text = iv
    final_signed_text += struct.pack("l", len(content))
    final_signed_text += content
    final_signed_text += signature

    return ensure_str(base64.b64encode(final_signed_text))


def validate_and_return_signed_str(secret: str, signed_text: str,
                                   valid_length: int=None) -> str:

    signed_text_reader = io.BytesIO(base64.b64decode(signed_text))
    iv = signed_text_reader.read(16)
    length = struct.unpack("l", encrypted_text_reader.read(8))[0]
    content = signed_text_reader.read(length)
    signature = signed_text_reader.read(32)

    hash = hmac.new(iv + ensure_bytes(secret), digestmod=hashlib.sha256)
    hash.update(ensure_bytes(content))
    if not hmac.compare_digest(signature, hash.digest()):
        return None

    timestamp = struct.unpack("l", content[:8])[0]
    text = content[8:]

    if valid_length and int(time.time()) - timestamp > valid_length:
        return None

    try:
        return ensure_str(text)
    except:
        return None


def encrypt_str_by_aes_gcm(secret: str, text: str) -> str:
    if AESCipher is None:
        raise Exception("Cryptography is not installed, "
                        "and aes_gcm_str_encrypt is called."
                        " Please install Cryptography through pip.")
    iv = os.urandom(16)

    content = struct.pack("l", int(time.time())) + ensure_bytes(text)

    encryptor = AESCipher(
        aes_algorithms.AES(ensure_bytes(secret)),
        aes_modes.GCM(iv),
        backend=aes_backend()
    ).encryptor()

    ciphertext = encryptor.update(content) + encryptor.finalize()

    final_encrypted_text = iv
    final_encrypted_text += struct.pack("l", len(ciphertext))
    final_encrypted_text += ciphertext
    final_encrypted_text += encryptor.tag

    return ensure_str(base64.b64encode(final_encrypted_text))


def decrypt_str_by_aes_gcm(secret: str, encrypted_text: str,
                           valid_length: int=None) -> str:
    if AESCipher is None:
        raise Exception("Cryptography is not installed, "
                        "and aes_gcm_str_decrypt is called."
                        " Please install Cryptography through pip.")
    encrypted_text_reader = io.BytesIO(base64.b64decode(encrypted_text))
    iv = encrypted_text_reader.read(16)
    length = struct.unpack("l", encrypted_text_reader.read(8))[0]
    ciphertext = encrypted_text_reader.read(length)
    tag = encrypted_text_reader.read(16)

    decryptor = AESCipher(
        aes_algorithms.AES(ensure_bytes(secret)),
        aes_modes.GCM(iv, tag),
        backend=aes_backend()
    ).decryptor()

    try:
        content = decryptor.update(ciphertext) + decryptor.finalize()
    except:
        return None

    timestamp = struct.unpack("l", content[:8])[0]
    text = content[8:]

    if valid_length and int(time.time()) - timestamp > valid_length:
        return None

    try:
        return ensure_str(text)
    except:
        return None
