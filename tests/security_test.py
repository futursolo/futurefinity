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

from futurefinity.utils import ensure_bytes

import futurefinity.security

import os
import time
import base64
import random
import unittest


class SecuirtyTestCollector(unittest.TestCase):
    def test_get_random_str(self):
        random_str_length = random.SystemRandom().choice(range(1, 1000))
        random_str = futurefinity.security.get_random_str(random_str_length)
        self.assertTrue(isinstance(random_str, str))
        self.assertEqual(len(random_str), random_str_length)

    def get_security_secret(self):
        if not hasattr(self, "_security_secret"):
            self._security_secret = futurefinity.security.get_random_str(32)
        return self._security_secret

    def get_aes_gcm_context(self):
        if not hasattr(self, "_aesgcm_context"):
            self._aesgcm_context = futurefinity.security.AESGCMSecurityContext(
                self.get_security_secret())
        return self._aesgcm_context

    def get_hmac_context(self):
        if not hasattr(self, "_hmac_context"):
            self._hmac_context = futurefinity.security.HMACSecurityContext(
                self.get_security_secret())
        return self._hmac_context

    def test_aes_gcm_not_allowed_type(self):
        context = self.get_aes_gcm_context()
        self.assertRaises(TypeError, context.generate_secure_text,
                          random.random())  # Test if only str is allowed.

    def test_hmac_not_allowed_type(self):
        context = self.get_hmac_context()
        self.assertRaises(TypeError, context.generate_secure_text,
                          random.random())  # Test if only str is allowed.

    def test_aes_gcm_successfully_encrypt_and_decrypt(self):
        context = self.get_aes_gcm_context()
        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        self.assertEqual(origin_text, context.lookup_origin_text(secure_text))

    def test_hmac_successfully_sign_and_verify(self):
        context = self.get_hmac_context()
        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        self.assertEqual(origin_text, context.lookup_origin_text(secure_text))

    def test_aes_gcm_unable_to_decode(self):
        context = self.get_aes_gcm_context()
        self.assertEqual(None, context.lookup_origin_text(os.urandom(32)))

    def test_hmac_unable_to_decode(self):
        context = self.get_hmac_context()
        self.assertEqual(None, context.lookup_origin_text(os.urandom(32)))

    def test_aes_gcm_unable_to_split(self):
        context = self.get_aes_gcm_context()
        self.assertEqual(None, context.lookup_origin_text(
            base64.b64encode(os.urandom(5))))

    def test_hmac_unable_to_split(self):
        context = self.get_hmac_context()
        self.assertEqual(None, context.lookup_origin_text(
            base64.b64encode(os.urandom(5))))

    def test_aes_gcm_verify_data(self):
        context = self.get_aes_gcm_context()
        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        failed_secure_text = bytearray(base64.b64decode(secure_text))
        del failed_secure_text[:-10]
        failed_secure_text += os.urandom(10)
        failed_secure_text = base64.b64encode(ensure_bytes(failed_secure_text))
        self.assertEqual(None, context.lookup_origin_text(failed_secure_text))

    def test_hmac_signature_mismatch(self):
        context = self.get_hmac_context()
        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)
        failed_secure_text = bytearray(base64.b64decode(secure_text))
        del failed_secure_text[:-10]
        failed_secure_text += os.urandom(10)
        failed_secure_text = base64.b64encode(ensure_bytes(failed_secure_text))
        self.assertEqual(None, context.lookup_origin_text(failed_secure_text))

    def test_aes_gcm_data_expire(self):
        context = self.get_aes_gcm_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        time.sleep(2)
        self.assertEqual(None, context.lookup_origin_text(secure_text, 1))

    def test_hmac_data_expire(self):
        context = self.get_hmac_context()

        origin_text = futurefinity.security.get_random_str(100)
        secure_text = context.generate_secure_text(origin_text)

        time.sleep(2)
        self.assertEqual(None, context.lookup_origin_text(secure_text, 1))
