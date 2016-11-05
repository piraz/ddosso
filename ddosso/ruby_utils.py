#!/usr/bin/env python
#
# Copyright 2016 Flavio Garcia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import urllib.parse
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from hashlib import sha1
import hmac
import binascii

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s)-1:])]


class RailsCookie(object):
    def __init__(self, secret_key_base, salt="encrypted cookie", keylen=64, iterations=1000):
        self.secret_key = secret_key_base.encode("ascii")
        self.secret = PBKDF2(self.secret_key, salt.encode("ascii"), keylen, iterations)

    def decrypt(self, cookie):
        first = urllib.parse.unquote(cookie)
        first = cookie
        print(first)
        second = first.split('--')[0]
        print(second)
        cookie = base64.b64decode(second)

        print(first.split('--')[1])

        encrypted_data, iv = map(base64.b64decode, cookie.decode().split('--'))
        #print(binascii.crc_hqx(encrypted_data))
        #hashed = hmac.new(self.secret_key, encrypted_data, hashlib.sha1)
        cipher = AES.new(self.secret[:32], AES.MODE_CBC, iv)

        plaintext = unpad(cipher.decrypt(encrypted_data))
        print(hmac.new(self.secret_key, encrypted_data,
                       digestmod=sha1).hexdigest())
        return plaintext

    def encrypt(self, raw):
        import html
        raw = pad(raw)

        iv = Random.new().read(AES.block_size)
        #iv = random_string(AES.block_size).encode('unicode_escape')
        #iv = b'\x8cE\\\x97-x|\xfd\xd2\x87\xa3C~]<\xac'
        cipher = AES.new(self.secret[:32], AES.MODE_CBC, iv)

        encrypted = cipher.encrypt(raw)
        buga = base64.b64encode(encrypted)
        iv_base64 = base64.b64encode(iv)
        separator = "--".encode('ascii')
        print(binascii.hexlify(self.secret_key))
        hexdigest = hmac.new(binascii.hexlify(self.secret_key), encrypted, digestmod=sha1).hexdigest().encode()
        print(hexdigest)
        return urllib.parse.quote_from_bytes((base64.b64encode(html.escape(buga.decode()).encode() + separator + iv_base64)) + separator + hexdigest).encode()
