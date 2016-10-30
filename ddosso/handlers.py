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

from . import discourse
from .forms import SigninForm, SignupForm
from .util import only_ajax, rooted_path
import base64

import firenado.tornadoweb
import firenado.security
from firenado import service


import hashlib
import hmac
import logging
import pika


import tornado.escape
from tornado.web import MissingArgumentError
from tornado import gen

import urllib.parse
import uuid

logger = logging.getLogger(__name__)


class RootedHandlerMixin:

    def get_rooted_path(self, path):
        root = self.component.conf['root']
        return rooted_path(root, path)


class IndexHandler(firenado.tornadoweb.TornadoHandler, RootedHandlerMixin):

    def get(self):
        self.redirect(self.get_rooted_path("/sign_in"), permanent=True)


class ProfileHandler(firenado.tornadoweb.TornadoHandler):

    def get(self):
        errors = None
        if self.session.has('errors'):
            errors = self.session.get('errors')
            self.session.delete('errors')
        ddosso_logo = self.component.conf['logo']
        self.render("profile.html", ddosso_conf=self.component.conf,
                    ddosso_logo=ddosso_logo, errors=errors)


class SigninHandler(firenado.tornadoweb.TornadoHandler, RootedHandlerMixin):

    def get(self):
        self.session.set("next_url", self.get_rooted_path("sign_in"))
        print(self.session.get("GOOGLE_ACCESS"))
        errors = None
        if self.session.has('errors'):
            errors = self.session.get('errors')
            self.session.delete('errors')
        ddosso_logo = self.component.conf['logo']
        self.render("sign_in.html", ddosso_conf=self.component.conf,
                    ddosso_logo=ddosso_logo, errors=errors)

    @service.served_by("ddosso.services.AccountService")
    def post(self):
        error_data = {'errors': {}}
        form = SigninForm(self.request.arguments, handler=self)
        if form.validate():
            self.set_status(200)
            account_data = form.data
            # Getting real ip from the nginx
            x_real_ip = self.request.headers.get("X-Real-IP")
            account_data['remote_ip'] = x_real_ip or self.request.remote_ip
            account_data['pod'] = self.component.conf[
                'diaspora']['url'].split("//")[1]
            #user = self.account_service.register(account_data)
            # data = {'id': "abcd1234",
            # 'next_url': self.get_rooted_path("profile")}
            # self.write(data)
        else:
            self.set_status(403)
            error_data['errors'].update(form.errors)
            self.write(error_data)


class SignupSocialHandler(firenado.tornadoweb.TornadoHandler,
                          RootedHandlerMixin):

    @only_ajax
    def post(self):
        conf = self.component.conf['social']
        social_data = {
            'authenticated': False,
            'type': None,
            'facebook': {'enabled': conf['facebook']['enabled']},
            'google': {'enabled': conf['google']['enabled']},
            'twitter': {'enabled': conf['twitter']['enabled']}
        }
        if conf['google']['enabled']:
            if self.session.has("google_user"):
                print(self.session.get("google_user"))
                social_data['authenticated'] = True
                social_data['type'] = "google"
        self.write(social_data)


class SignupHandler(firenado.tornadoweb.TornadoHandler, RootedHandlerMixin):

    def __init__(self, application, request, **kwargs):
        from tornado.locks import Condition
        super(SignupHandler, self).__init__(application, request, **kwargs)
        self.callback_queue = None
        self.condition = Condition()
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.in_channel = self.application.get_app_component().rabbitmq[
            'client'].channels['in']

    def get(self):
        errors = None
        if self.session.has('errors'):
            errors = self.session.get('errors')
            self.session.delete('errors')
        ddosso_logo = self.component.conf['logo']
        self.session.set("next_url", self.get_rooted_path("sign_up"))
        self.render("sign_up.html", ddosso_conf=self.component.conf,
                    ddosso_logo=ddosso_logo, errors=errors)

    @service.served_by("ddosso.services.AccountService")
    def post(self):
        error_data = {'errors': {}}
        form = SignupForm(self.request.arguments, handler=self)
        if form.validate():
            self.set_status(200)
            account_data = form.data
            # Getting real ip from the nginx
            x_real_ip = self.request.headers.get("X-Real-IP")
            account_data['remote_ip'] = x_real_ip or self.request.remote_ip
            account_data['pod'] = self.component.conf[
                'diaspora']['url'].split("//")[1]
            #user = self.account_service.register(account_data)
            #data = {'id': "abcd1234",
                    #'next_url': self.get_rooted_path("profile")}
            #self.write(data)
        else:
            self.set_status(403)
            error_data['errors'].update(form.errors)
            self.write(error_data)


class DiscourseSSOHandler(firenado.tornadoweb.TornadoHandler):

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
        self.session.clear()
        self.session.set("payload", payload)
        self.session.set("signature", signature)
        self.session.set("goto", "discourse")
        #self.print(tornado.escape.url_unescape(sso_data['return_sso_url']))
        self.redirect("login")


class LoginHandler(firenado.tornadoweb.TornadoHandler):


    def get(self):
        errors = {}
        if self.session.has('login_errors'):
            errors = self.session.get('login_errors')

        ddosso_logo = self.component.conf['logo']
        #print(self.session.get("payload"))
        #print(self.session.get("signature"))

        self.render("discourse/login.html", ddosso_conf=self.component.conf,
                    ddosso_logo=ddosso_logo, errors=errors)

    @service.served_by("ddosso.services.LoginService")
    @service.served_by("ddosso.services.UserService")
    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        errors = {}

        if username == "":
            errors['username'] = "Please inform the username"
        if password == "":
            errors['password'] = "Please inform the password"

        self.session.delete('login_errors')
        user = None
        if not errors:
            user = self.login_service.is_valid(username, password)
            if not user:
                errors['fail'] = "Invalid login"

        if errors:
            self.session.set('login_errors', errors)
            self.redirect("login")
            return
        else:
            # Getting real ip from the nginx
            x_real_ip = self.request.headers.get("X-Real-IP")
            remote_ip = x_real_ip or self.request.remote_ip
            #self.user_service.set_user_seem(user, remote_ip)

        sso_data = discourse.get_sso_data(self.session.get("payload"))
        params = {
            'nonce': sso_data['nonce'],
            'email': user['email'],
            'external_id': user['guid'],
            'username': user['username'],
            'name': user['name'],
            'avatar_url': user['avatar']
        }

        secret = self.component.conf['discourse']['sso']['secret']
        return_sso_url = tornado.escape.url_unescape(
            sso_data['return_sso_url'])
        return_payload = base64.encodebytes(
            urllib.parse.urlencode(params).encode())
        h = hmac.new(secret.encode(), return_payload, digestmod=hashlib.sha256)
        query_string = urllib.parse.urlencode(
            {'sso': return_payload, 'sig': h.hexdigest()})
        return_path = '%s?%s' % (return_sso_url, query_string)
        self.redirect(return_path)


class CaptchaHandler(firenado.tornadoweb.TornadoHandler):

    def __init__(self, application, request, **kwargs):
        from tornado.locks import Condition
        super(CaptchaHandler, self).__init__(application, request, **kwargs)
        self.name = None
        self.callback_queue = None
        self.condition = Condition()
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.in_channel = self.application.get_app_component().rabbitmq[
            'client'].channels['in']

    @only_ajax
    @gen.coroutine
    def post(self, name):
        self.name = name
        self.in_channel.queue_declare(exclusive=True,
                                      callback=self.on_request_queue_declared)
        yield self.condition.wait()

        self.write(self.response)

    @gen.coroutine
    def on_request_queue_declared(self, response):
        logger.info('Request temporary queue declared for captcha.')
        from firenado.util import random_string
        string = random_string(5).lower()
        self.session.set("captcha_string_%s" % self.name, string)
        self.callback_queue = response.method.queue
        self.in_channel.basic_consume(self.on_response, no_ack=True,
                                      queue=self.callback_queue)
        self.in_channel.basic_publish(
            exchange='',
            routing_key='ddosso_captcha_rpc_queue',
            properties=pika.BasicProperties(
                reply_to=self.callback_queue,
                correlation_id=self.corr_id,
            ),
            body=string)

    def on_response(self, ch, method, props, body):
        if self.corr_id == props.correlation_id:
            self.response = {
                "id": self.name,
                "captcha": "data:image/png;base64,%s" % body.decode("utf-8")
            }
            self.in_channel.queue_delete(queue=self.callback_queue)
            self.condition.notify()
