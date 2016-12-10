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

import futurefinity

import os
import base64
import pytest
import random

_undecodable_bytes = \
    b"\xba\xe83\xc4y\"\xd3^P\xc1\x06\x15Y\xd9\xde\x93cJ\xfe\xb8++C\x03p6\x95"


def get_security_secret():
    return futurefinity.security.get_random_str(32)


def get_aes_context():
    return futurefinity.security.AESContext(get_security_secret())


def get_hmac_context():
    return futurefinity.security.HMACSecurityContext(get_security_secret())


class GetRandomStrFnTestCase:
    def test_get_random_str(self):
        random_str_length = random.SystemRandom().choice(range(1, 1000))

        random_str = futurefinity.security.get_random_str(random_str_length)

        assert isinstance(random_str, str)
        assert len(random_str) == random_str_length


class AESContextTestCase:
    def test_aes_not_allowed_type(self):
        context = get_aes_context()

        with pytest.raises(TypeError):
            context.generate_secure_text(-1)
        # Test if only str is allowed.

    def test_aes_encrypt_and_decrypt(self):
        context = get_aes_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        assert origin_text == context.lookup_origin_text(secure_text)

    def test_aes_unable_to_decode(self):
        context = get_aes_context()

        assert context.lookup_origin_text(_undecodable_bytes) is None

    def test_aes_unable_to_split(self):
        context = get_aes_context()

        assert context.lookup_origin_text(
            base64.b64encode(os.urandom(5))) is None

    def test_aes_verify_data(self):
        context = get_aes_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        failed_secure_text = bytearray(base64.b64decode(secure_text))

        del failed_secure_text[-10:]

        failed_secure_text += os.urandom(10)
        failed_secure_text = base64.b64encode(
            futurefinity.encoding.ensure_bytes(failed_secure_text))

        assert context.lookup_origin_text(failed_secure_text) is None

    def test_aes_gcm_data_expire(self):
        context = get_aes_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        assert context.lookup_origin_text(secure_text, -1) is None


class HMACSecurityContextTestCase:
    def test_hmac_not_allowed_type(self):
        context = get_hmac_context()

        with pytest.raises(TypeError):
            context.generate_secure_text(-1)
        # Test if only str is allowed.

    def test_hmac_sign_and_verify(self):
        context = get_hmac_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        assert origin_text == context.lookup_origin_text(secure_text)

    def test_hmac_unable_to_decode(self):
        context = get_hmac_context()

        assert context.lookup_origin_text(_undecodable_bytes) is None

    def test_hmac_unable_to_split(self):
        context = get_hmac_context()

        assert context.lookup_origin_text(
            base64.b64encode(os.urandom(5))) is None

    def test_hmac_signature_mismatch(self):
        context = get_hmac_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        failed_secure_text = bytearray(base64.b64decode(secure_text))

        del failed_secure_text[-10:]

        failed_secure_text += os.urandom(10)
        failed_secure_text = base64.b64encode(
            futurefinity.encoding.ensure_bytes(failed_secure_text))

        assert context.lookup_origin_text(failed_secure_text) is None

    def test_hmac_data_expire(self):
        context = get_hmac_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        assert context.lookup_origin_text(secure_text, -1) is None
