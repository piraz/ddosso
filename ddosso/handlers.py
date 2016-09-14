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

# See: http://bit.ly/2cj7IRS

import firenado.tornadoweb
import tornado.escape
from tornado.web import MissingArgumentError
from . import discourse
import base64
import urllib.parse
import hmac
import hashlib


class IndexHandler(firenado.tornadoweb.TornadoHandler):

    def get(self):
        payload = self.get_argument("sso", strip=False)
        signature = self.get_argument("sig")
        secret = self.component.conf['discourse']['sso']['secret']

        if None in [payload, signature]:
            raise MissingArgumentError("No SSO payload or signature. Please "
                                       "contact support if this problem "
                                       "persists.")
        try:
            assert discourse.sso_has_nounce(payload)
        except AssertionError:
            return MissingArgumentError("Invalid payload. Please contact "
                                        "support if this problem persists.")

        if not discourse.sso_validate(payload, signature, secret):
            raise MissingArgumentError("Invalid payload. Please contact "
                                       "support if this problem persists.")

        self.session.set("payload", payload)
        self.session.set("secret", secret)
        errors = {}
        if self.session.has('login_errors'):
            errors = self.session.get('login_errors')

        sso_data = discourse.get_sso_data(payload)

        params = {
            'nonce': sso_data['nonce'],
            'email': "test1@test.ts",
            'external_id': "1ab",
            'username': "test1",
            'name': "Monster1 of lake"
        }
        return_sso_url = tornado.escape.url_unescape(sso_data['return_sso_url'])

        return_payload = base64.encodebytes(urllib.parse.urlencode(params).encode())
        h = hmac.new(secret.encode(), return_payload, digestmod=hashlib.sha256)
        query_string = urllib.parse.urlencode(
            {'sso': return_payload, 'sig': h.hexdigest()})
        return_path = '%s?%s' % (return_sso_url, query_string)
        #self.print(tornado.escape.url_unescape(sso_data['return_sso_url']))
        #self.redirect(return_path)
        self.render("index.html", ddosso_conf=self.component.conf,
                    errors=errors)

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        errors = {}

        if username == "":
            errors['username'] = "Please inform the username"
        if password == "":
            errors['password'] = "Please inform the password"

        self.session.delete('login_errors')

        if errors:
            self.session.set('login_errors', errors)
            self.redirect("login")


class LoginHandler(firenado.tornadoweb.TornadoHandler):

    USERNAME = "test"
    PASSWORD = "test"  # noqa

    def get(self):
        errors = {}
        if self.session.has('login_errors'):
            errors = self.session.get('login_errors')
        self.render("login.html", errors=errors)

