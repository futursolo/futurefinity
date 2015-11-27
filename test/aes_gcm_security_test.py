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

from futurefinity.utils import *
import unittest
import nose2
import time


class AESGCMSecurityTestCollector(unittest.TestCase):
    def test_aes_gcm_security(self):
        text = security_secret_generator(1024)
        key = security_secret_generator(16)
        encrypted = encrypt_str_by_aes_gcm(key, text)
        decrypted = decrypt_str_by_aes_gcm(key, encrypted)

        self.assertEqual(text, decrypted, "Cannot Decrypt Content!")

    def test_aes_gcm_expire_security(self):
        text = security_secret_generator(1024)
        key = security_secret_generator(16)
        encrypted = encrypt_str_by_aes_gcm(key, text)
        time.sleep(2)
        decrypted = decrypt_str_by_aes_gcm(key, encrypted, valid_length=1)

        self.assertEqual(None, decrypted, "Cannot Decrypt Content!")
