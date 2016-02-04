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

from futurefinity.utils import ensure_str, ensure_bytes

import io
import os
import hmac
import time
import base64
import string
import struct
import random
import hashlib

try:  # Try to load cryptography.
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as AESCipher,
        algorithms as aes_algorithms,
        modes as aes_modes
    )
    from cryptography.hazmat.backends import default_backend as aes_backend

except ImportError:  # Point cryptography to None if they are not found.
    AESCipher = None
    aes_algorithms = None
    aes_modes = None
    aes_backend = None


def get_random_str(length: int) -> str:
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
            string.ascii_letters + string.digits)
    return random_string


class HMACSecurityObject:
    def __init__(self, security_secret: str):
        self.__security_secret = hashlib.sha256(
            ensure_bytes(security_secret)).digest()

    def lookup_origin_text(self, secure_text: str,
                           valid_length: int=None) -> str:

        signed_text_reader = io.BytesIO(base64.b64decode(secure_text))

        iv = signed_text_reader.read(16)
        length = struct.unpack("l", signed_text_reader.read(8))[0]
        content = signed_text_reader.read(length)
        signature = signed_text_reader.read(32)

        hash = hmac.new(iv + ensure_bytes(self.__security_secret),
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
        iv = os.urandom(16)

        content = struct.pack(
            "l", int(time.time())) + ensure_bytes(origin_text)
        hash = hmac.new(iv + ensure_bytes(self.__security_secret),
                        digestmod=hashlib.sha256)
        hash.update(ensure_bytes(content))
        signature = hash.digest()

        final_signed_text = iv
        final_signed_text += struct.pack("l", len(content))
        final_signed_text += content
        final_signed_text += signature

        return ensure_str(base64.b64encode(final_signed_text))


class AESGCMSecurityObject:
    def __init__(self, security_secret: str):
        if None in [AESCipher, aes_algorithms, aes_modes, aes_backend]:
            raise Exception(
                "Currently, `futurefinity.security.AESGCMSecurityObject` "
                "needs Cryptography to work. Please install it before "
                "using security features(such as security_secret), "
                "or turn aes_security to False in Application Settings.")

        self.__security_secret = hashlib.sha256(
            ensure_bytes(security_secret)).digest()

    def lookup_origin_text(self, secure_text: str,
                           valid_length: int=None) -> str:
        encrypted_text_reader = io.BytesIO(base64.b64decode(secure_text))

        iv = encrypted_text_reader.read(16)
        length = struct.unpack("l", encrypted_text_reader.read(8))[0]
        ciphertext = encrypted_text_reader.read(length)
        tag = encrypted_text_reader.read(16)

        decryptor = AESCipher(
            aes_algorithms.AES(ensure_bytes(self.__security_secret)),
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
        iv = os.urandom(16)

        content = struct.pack(
            "l", int(time.time())) + ensure_bytes(origin_text)

        encryptor = AESCipher(
            aes_algorithms.AES(ensure_bytes(self.__security_secret)),
            aes_modes.GCM(iv),
            backend=aes_backend()
        ).encryptor()

        ciphertext = encryptor.update(content) + encryptor.finalize()

        final_encrypted_text = iv
        final_encrypted_text += struct.pack("l", len(ciphertext))
        final_encrypted_text += ciphertext
        final_encrypted_text += encryptor.tag

        return ensure_str(base64.b64encode(final_encrypted_text))
