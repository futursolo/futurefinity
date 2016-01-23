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

from futurefinity.utils import *

import io
import os
import hmac
import time
import base64
import typing
import struct
import hashlib

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


class SecureCookieInterfaceModel:
    """
    Model Of all the Secure Cookie Interface.
    """
    def __init__(self, app=None, security_secret=None, *args, **kwargs):
        self.app = app
        self._initialized = False
        self.security_secret = security_secret

    def initialize(self, app=None, security_secret=None):
        if self._initialized:
            return
        if app:
            self.app = app
        if not self.app:
            raise Exception(
                "FutureFinity Application is not set for this Interface.")
        if security_secret:
            self.security_secret = security_secret
        if not self.security_secret:
            self.security_secret = self.app.settings.get(
                "security_secret", None)
        self._initialized = True

    def lookup_origin_text(self, secure_text: str) -> str:
        raise NotImplementedError("No Secure Cookie Interface Available.")

    def generate_secure_text(self, origin_text: str) -> str:
        raise NotImplementedError("No Secure Cookie Interface Available.")


class HMACSecureCookieInterface(SecureCookieInterfaceModel):
    def lookup_origin_text(self, secure_text: str,
                           valid_length: int=None) -> str:
        if not self.security_secret:
            raise Exception(
                "Cannot found Security Secret. "
                "Please provide security_secret through Application "
                "Settings or __init__ security_secret Parameter.")
        signed_text_reader = io.BytesIO(base64.b64decode(secure_text))

        iv = signed_text_reader.read(16)
        length = struct.unpack("l", signed_text_reader.read(8))[0]
        content = signed_text_reader.read(length)
        signature = signed_text_reader.read(32)

        hash = hmac.new(iv + ensure_bytes(self.security_secret),
                        digestmod=hashlib.sha256)
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

    def generate_secure_text(self, origin_text: str) -> str:
        if not self.security_secret:
            raise Exception(
                "Cannot found Security Secret. "
                "Please provide security_secret through Application "
                "Settings or __init__ security_secret Parameter.")
        iv = os.urandom(16)

        content = struct.pack(
            "l", int(time.time())) + ensure_bytes(origin_text)
        hash = hmac.new(iv + ensure_bytes(self.security_secret),
                        digestmod=hashlib.sha256)
        hash.update(ensure_bytes(content))
        signature = hash.digest()

        final_signed_text = iv
        final_signed_text += struct.pack("l", len(content))
        final_signed_text += content
        final_signed_text += signature

        return ensure_str(base64.b64encode(final_signed_text))


class AESGCMSecureCookieInterface(SecureCookieInterfaceModel):
    def initialize(self, *args, **kwargs):
        SecureCookieInterfaceModel.initialize(self, *args, **kwargs)

        if None in [AESCipher, aes_algorithms, aes_modes, aes_backend]:
            raise Exception("Cryptography is not installed, "
                            "and aes_gcm_str_encrypt is called."
                            " Please install Cryptography through pip.")

    def lookup_origin_text(self, secure_text: str,
                           valid_length: int=None) -> str:
        if not self.security_secret:
            raise Exception(
                "Cannot found Security Secret. "
                "Please provide security_secret through Application "
                "Settings or __init__ security_secret Parameter.")
        encrypted_text_reader = io.BytesIO(base64.b64decode(secure_text))

        iv = encrypted_text_reader.read(16)
        length = struct.unpack("l", encrypted_text_reader.read(8))[0]
        ciphertext = encrypted_text_reader.read(length)
        tag = encrypted_text_reader.read(16)

        decryptor = AESCipher(
            aes_algorithms.AES(ensure_bytes(self.security_secret)),
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

    def generate_secure_text(self, origin_text: str) -> str:
        if not self.security_secret:
            raise Exception(
                "Cannot found Security Secret. "
                "Please provide security_secret through Application "
                "Settings or __init__ security_secret Parameter.")
        iv = os.urandom(16)

        content = struct.pack(
            "l", int(time.time())) + ensure_bytes(origin_text)

        encryptor = AESCipher(
            aes_algorithms.AES(ensure_bytes(self.security_secret)),
            aes_modes.GCM(iv),
            backend=aes_backend()
        ).encryptor()

        ciphertext = encryptor.update(content) + encryptor.finalize()

        final_encrypted_text = iv
        final_encrypted_text += struct.pack("l", len(ciphertext))
        final_encrypted_text += ciphertext
        final_encrypted_text += encryptor.tag

        return ensure_str(base64.b64encode(final_encrypted_text))


if None not in [AESCipher, aes_algorithms, aes_modes, aes_backend]:
    DefaultSecureCookieInterface = AESGCMSecureCookieInterface
else:
    DefaultSecureCookieInterface = HMACSecureCookieInterface
