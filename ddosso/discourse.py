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
from hashlib import sha256
import hmac
from base64 import b64decode, b64encode, decodebytes, encodebytes


def sso_validate(payload, signature, secret):
    payload = urllib.parse.unquote(payload)
    computed_sig = hmac.new(
        secret.encode(),
        payload.encode(),
        sha256
    ).hexdigest()
    return hmac.compare_digest(computed_sig, signature)


def sso_has_nounce(payload):
    payload = urllib.parse.unquote(payload)
    decoded = decodebytes(payload.encode()).decode()
    return 'nonce' in decoded


def get_sso_data(payload):
    decoded = decodebytes(payload.encode()).decode()
    return dict(data.split("=") for data in decoded.split('&'))


def build_sso_login_url(nonce, redirect_uri, secret):
    data = {
        'nonce': nonce,
        'return_sso_url': redirect_uri
    }

    payload = urllib.parse.urlencode(data)
    payload = b64encode(payload.encode())
    sig = hmac.new(secret.encode('utf-8'), payload, sha256).hexdigest()

    return '/session/sso_provider?' + urllib.parse.urlencode(
        {'sso': payload, 'sig': sig})
