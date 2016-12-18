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

from .forms import SigninForm, SignupForm
from .util import only_ajax, rooted_path

import firenado.security
from firenado import security
from firenado import service

import logging
import pika
import tornado.escape
from tornado import gen
import uuid

logger = logging.getLogger(__name__)

DIASPORA_SESSION_COOKIE = "_diaspora_session"
FACEBOOK_USER = "facebook_user"
GOOGLE_USER = "google_user"
TWITTER_USER = "twitter_user"


class DdossoHandlerMixin:

    @service.served_by("ddosso.services.UserService")
    def is_logged(self):
        from .ruby_utils import RailsCookie
        conf = self.component.conf['diaspora']
        rails_cookie = RailsCookie(conf['cookie']['secret'])
        cookie = self.get_cookie(DIASPORA_SESSION_COOKIE, None)
        if cookie:
            if rails_cookie.is_valid(cookie):
                cookie_data = rails_cookie.decrypt(cookie).decode()
                rails_session = tornado.escape.json_decode(cookie_data)
                if 'warden.user.user.key' in rails_session:
                    user_id = rails_session['warden.user.user.key'][0][0]
                    pass_partial = rails_session['warden.user.user.key'][1]
                    user = self.user_service.by_id(user_id)
                    if user:
                        if user.encrypted_password[:29] == pass_partial:
                            if user.locked_at is None:
                                return True
            self.clear_cookie(DIASPORA_SESSION_COOKIE)
        return False

    def get_current_user(self):
        return self.get_logged_user()

    @service.served_by("ddosso.services.UserService")
    def get_logged_user(self):
        from .ruby_utils import RailsCookie
        conf = self.component.conf['diaspora']
        rails_cookie = RailsCookie(conf['cookie']['secret'])
        cookie = self.get_cookie(DIASPORA_SESSION_COOKIE, None)
        if cookie:
            if rails_cookie.is_valid(cookie):
                cookie_data = rails_cookie.decrypt(cookie).decode()
                rails_session = tornado.escape.json_decode(cookie_data)
                if 'warden.user.user.key' in rails_session:
                    user_id = rails_session['warden.user.user.key'][0][0]
                    pass_partial = rails_session['warden.user.user.key'][1]
                    user = self.user_service.by_id(user_id)
                    if user:
                        return user
        return None

    @service.served_by("ddosso.services.UserService")
    def sing_in_user(self, user):
        from .ruby_utils import RailsCookie
        conf = self.component.conf['diaspora']
        rails_cookie = RailsCookie(conf['cookie']['secret'])
        session_data = {
            'session_id': str(rails_cookie.gen_cookie_id()),
            'warden.user.user.key': [
                [user.id],
                user.encrypted_password[:29],
            ]
        }
        self.set_cookie(DIASPORA_SESSION_COOKIE, rails_cookie.encrypt(
            tornado.escape.json_encode(session_data)))
        # Getting real ip from the nginx
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip
        self.user_service.set_user_seem({'username': user.username},
                                        remote_ip)

    def get_rooted_path(self, path):
        root = self.component.conf['root']
        return rooted_path(root, path)

    def is_signin_next(self):
        sign_in_url = self.get_rooted_path("sign_in")
        return sign_in_url in self.session.get("next_url")

    def is_signup_next(self):
        sign_up_url = self.get_rooted_path("sign_up")
        return sign_up_url in self.session.get("next_url")


class IndexHandler(firenado.tornadoweb.TornadoHandler, DdossoHandlerMixin):

    def get(self):
        self.redirect(self.get_rooted_path("/sign_in"), permanent=True)


class ProfileHandler(DdossoHandlerMixin, firenado.tornadoweb.TornadoHandler):

    @security.authenticated
    @service.served_by("ddosso.services.PersonService")
    @service.served_by("ddosso.services.ProfileService")
    @service.served_by("ddosso.services.TagService")
    @service.served_by("ddosso.services.SocialLinkService")
    def get(self):
        user = self.get_current_user()
        person = self.person_service.by_user(user)
        profile = self.profile_service.by_person(person)
        tags = self.tag_service.by_user(user)
        social_links = {
            'facebook': None,
            'google': None,
            'twitter': None
        }
        for social_link in self.social_link_service.by_user(user):
            if social_link.type == 'Oauth2:Facebook':
                social_links['facebook'] = social_link
            if social_link.type == 'Oauth2: Google':
                social_links['google'] = social_link
            if social_link.type == 'Oauth:Twitter':
                social_links['twitter'] = social_link
        account = {
            'user': user,
            'person': person,
            'profile': profile,
            'tags': tags,
        }
        errors = None
        if self.session.has('errors'):
            errors = self.session.get('errors')
            self.session.delete('errors')
        ddosso_logo = self.component.conf['logo']
        self.render("profile.html", account=account,
                    ddosso_conf=self.component.conf, ddosso_logo=ddosso_logo,
                    social_links=social_links, errors=errors)


class DiasporaProfileHandler(DdossoHandlerMixin,
                             firenado.tornadoweb.TornadoHandler):

    @security.authenticated
    @only_ajax
    @service.served_by("ddosso.services.PersonService")
    @service.served_by("ddosso.services.ProfileService")
    @service.served_by("ddosso.services.TagService")
    def post(self):
        user = self.get_current_user()
        person = self.person_service.by_user(user)
        profile = self.profile_service.by_person(person)
        tags = self.tag_service.by_user(user)
        account = {
            'diaspora_url': self.component.conf['diaspora']['url'],
            'profile': {
                'profile_id': profile.id,
                'user_id': user.id,
                'username': user.username,
                'image_url': profile.get_image_url(),
                'first_name': profile.first_name,
                'last_name': profile.last_name,
                'handler': "%s@%s" % (user.username,
                                      self.component.conf[
                                          'diaspora']['domain']),
                'bio': profile.bio,
            },
            'tags': [],
        }
        for tag in tags:
            account['tags'].append({'id': tag.id, 'name': tag.name,})
        self.write(account)


class SigninHandler(firenado.tornadoweb.TornadoHandler, DdossoHandlerMixin):

    def get(self):
        if self.is_logged():
            self.redirect("/")
        else:
            self.session.set("next_url", self.get_rooted_path("sign_in"))
            errors = None
            if self.session.has('errors'):
                errors = self.session.get('errors')
                self.session.delete('errors')
            ddosso_logo = self.component.conf['logo']
            self.render("sign_in.html", ddosso_conf=self.component.conf,
                        ddosso_logo=ddosso_logo, errors=errors)

    @service.served_by("ddosso.services.UserService")
    def post(self):
        error_data = {'errors': {}}
        form = SigninForm(self.request.arguments, handler=self)
        if form.validate():
            account_data = form.data
            user = self.user_service.by_username(account_data['username'])
            self.sing_in_user(user)
            self.set_status(200)
            data = {'id': account_data['username'], 'next_url': "/"}
            self.write(data)
        else:
            self.set_status(403)
            error_data['errors'].update(form.errors)
            self.write(error_data)


class SignupHandler(firenado.tornadoweb.TornadoHandler, DdossoHandlerMixin):

    def __init__(self, application, request, **kwargs):
        from tornado.locks import Condition
        super(SignupHandler, self).__init__(application, request, **kwargs)
        self.callback_queue = None
        self.condition = Condition()
        self.account_data = None
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.in_channel = self.application.get_app_component().rabbitmq[
            'client'].channels['in']

    def get(self):
        if self.is_logged():
            self.redirect("/")
        else:
            errors = None
            if self.session.has('errors'):
                errors = self.session.get('errors')
                self.session.delete('errors')
            ddosso_logo = self.component.conf['logo']
            self.session.set("next_url", self.get_rooted_path("sign_up"))
            self.render("sign_up.html", ddosso_conf=self.component.conf,
                        ddosso_logo=ddosso_logo, errors=errors)

    @gen.coroutine
    @service.served_by("ddosso.services.AccountService")
    def post(self):
        error_data = {'errors': {}}
        form = SignupForm(self.request.arguments, handler=self)
        if form.validate():
            self.set_status(200)
            self.account_data = form.data
            self.account_data['social'] = []
            # Getting real ip from the nginx
            x_real_ip = self.request.headers.get("X-Real-IP")
            self.account_data['remote_ip'] = x_real_ip or self.request.remote_ip
            self.account_data['pod'] = self.component.conf[
                'diaspora']['url'].split("//")[1]
            self.in_channel.queue_declare(
                exclusive=True, callback=self.on_request_queue_declared)
            yield self.condition.wait()
            if self.session.has(FACEBOOK_USER):
                facebook_user = tornado.escape.json_decode(
                    self.session.get(FACEBOOK_USER))
                data = {
                    'type': "Oauth2:Facebook",
                    'data': self.session.get(FACEBOOK_USER),
                    'handler': facebook_user['id'],
                }
                self.account_data['social'].append(data)
            if self.session.has(GOOGLE_USER):
                google_user = tornado.escape.json_decode(
                    self.session.get(GOOGLE_USER))
                data = {
                    'type': "Oauth2:Google",
                    'data': self.session.get(GOOGLE_USER),
                    'handler': google_user['email'],
                }
                self.account_data['social'].append(data)
            if self.session.has(TWITTER_USER):
                twitter_user = tornado.escape.json_decode(
                    self.session.get(TWITTER_USER))
                data = {
                    'type': "Oauth:Twitter",
                    'data': self.session.get(TWITTER_USER),
                    'handler': twitter_user['username'],
                }
                self.account_data['social'].append(data)
            user = self.account_service.register(self.account_data)
            data = {'id': self.account_data['username'], 'next_url': "/"}
            self.write(data)
        else:
            self.set_status(403)
            error_data['errors'].update(form.errors)
            self.write(error_data)

    def on_request_queue_declared(self, response):
        import copy
        account_data = copy.copy(self.account_data)
        account_data['password'] = "*" * len(account_data['password'])
        account_data['passwordConf'] = account_data['password']
        logger.info("Request temporary queue declared to generate private key "
                    "for account %s." % account_data)
        self.callback_queue = response.method.queue
        self.in_channel.basic_consume(self.on_response, no_ack=True,
                                      queue=self.callback_queue)
        self.in_channel.basic_publish(
            exchange='',
            routing_key='ddosso_keygen_rpc_queue',
            properties=pika.BasicProperties(
                reply_to=self.callback_queue,
                correlation_id=self.corr_id,
            ),
            body=tornado.escape.json_encode(account_data))

    def on_response(self, ch, method, props, body):
        if self.corr_id == props.correlation_id:
            import copy
            import base64
            account_data = copy.copy(self.account_data)
            account_data['password'] = "*" * len(account_data['password'])
            account_data['passwordConf'] = account_data['password']
            logger.info("Received private key for account %s." % account_data)
            self.account_data['private_key'] = base64.b64decode(
                body).decode('ascii')
            self.in_channel.queue_delete(queue=self.callback_queue)
            self.condition.notify()


class SocialHandler(firenado.tornadoweb.TornadoHandler, DdossoHandlerMixin):

    @only_ajax
    def post(self, name):
        conf = self.component.conf['social']
        social_data = {
            'authenticated': False,
            'type': None,
            'picture': None,
            'first_name': None,
            'last_name': None,
            'email': None,
            'facebook': {'enabled': conf['facebook']['enabled']},
            'google': {'enabled': conf['google']['enabled']},
            'twitter': {'enabled': conf['twitter']['enabled']}
        }
        if conf['facebook']['enabled']:
            if name == "sign_in":
                self.session.delete(FACEBOOK_USER)
            if self.session.has(FACEBOOK_USER):
                facebook_user = tornado.escape.json_decode(
                    self.session.get(FACEBOOK_USER))
                social_data['authenticated'] = True
                social_data['type'] = "facebook"
                social_data['handler'] = facebook_user['name']
                social_data['picture'] = facebook_user[
                    'picture']['data']['url']
                social_data['first_name'] = facebook_user['first_name']
                social_data['last_name'] = facebook_user['last_name']
        if conf['google']['enabled']:
            if name == "sign_in":
                self.session.delete(GOOGLE_USER)
            if self.session.has(GOOGLE_USER):
                google_user = tornado.escape.json_decode(
                    self.session.get(GOOGLE_USER))
                social_data['authenticated'] = True
                social_data['type'] = "google"
                social_data['handler'] = google_user['email']
                social_data['picture'] = google_user['picture']
                social_data['first_name'] = google_user['given_name']
                social_data['last_name'] = google_user['family_name']
        if conf['twitter']['enabled']:
            if name == "sign_in":
                self.session.delete(TWITTER_USER)
            if self.session.has(TWITTER_USER):
                twitter_user = tornado.escape.json_decode(
                    self.session.get(TWITTER_USER))
                social_data['authenticated'] = True
                social_data['type'] = "twitter"
                social_data['handler'] = twitter_user['username']
                social_data['picture'] = twitter_user[
                    'profile_image_url_https'].replace("_normal", "_400x400")
                social_data['first_name'] = twitter_user['name']
                social_data['last_name'] = ""
        self.write(social_data)

    def delete(self, name):
        conf = self.component.conf['social']
        if conf['facebook']['enabled']:
            if self.session.has(FACEBOOK_USER):
                self.session.delete(FACEBOOK_USER)
        if conf['google']['enabled']:
            if self.session.has(GOOGLE_USER):
                self.session.delete(GOOGLE_USER)
        if conf['twitter']['enabled']:
            if self.session.has(TWITTER_USER):
                self.session.delete(TWITTER_USER)
        social_data = {
            'deleted': True,
        }
        self.write(social_data)


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
