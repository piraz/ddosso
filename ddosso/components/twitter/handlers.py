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

from ddosso.handlers import DdossoHandlerMixin

import firenado.conf
import firenado.tornadoweb
from firenado import service

from tornado.auth import TwitterMixin
from tornado.escape import json_encode, json_decode
from tornado import gen

import logging

logger = logging.getLogger(__name__)


class TwitterHandlerMixin:

    SESSION_KEY = 'twitter_user'

    def get_current_user(self):
        user_json = self.session.get(self.SESSION_KEY)
        if not user_json:
            return None
        return json_decode(user_json)


class TwitterOauthHandler(TwitterHandlerMixin,
                          firenado.tornadoweb.TornadoHandler,
                          DdossoHandlerMixin):

    @firenado.security.authenticated("twitter")
    @service.served_by("ddosso.services.SocialLinkService")
    @service.served_by("ddosso.services.UserService")
    def get(self):
        errors = {}
        twitter_user = self.current_user
        logger.info("Authenticated twitter profile %s being redirected." %
                    twitter_user['username'])
        if self.is_signin_next():
            logger.info("User is trying to sign in with the twitter profile "
                        "%s." % twitter_user['username'])
            social_link = self.social_link_service.by_handler("Oauth:Twitter",
                                                twitter_user['username'])
            if social_link:
                user = self.user_service.by_id(social_link.user_id)
                logger.info("User %s associated with the twitter profile %s."
                            "Signing in user." % (user.username,
                                                  twitter_user['username']))
                self.sing_in_user(user)
                self.session.delete(self.SESSION_KEY)
            else:
                logger.error("The twitter profile %s is not associated with"
                             "any account. Sign in failed. Sending error to "
                             "sign in form." % twitter_user['username'])
                self.session.delete(self.SESSION_KEY)
                errors['request'] = ("Este perfil do twitter não está "
                                     "associado com nenhuma conta. Login "
                                     "inválido.")
                self.session.set("errors", errors)
            self.redirect(self.session.get("next_url"))
        elif self.is_signup_next():
            logger.info("User is trying to create a new account associated"
                        " with a twitter profile %s." %
                        twitter_user['username'])
            if self.social_link_service.by_handler("Oauth:Twitter",
                                                   twitter_user['username']):
                logger.error("The twitter profile %s is already associated "
                             "with an existent account. "
                             "Sending an error to sign up form." %
                             twitter_user['username'])
                self.session.delete(self.SESSION_KEY)
                errors['request'] = ("Este perfil do twitter já está "
                                     "associado a outra conta. Não é possivel "
                                     "associá-lo a um novo usuário.")
                self.session.set("errors", errors)
            self.redirect(self.session.get("next_url"))
        else:
            self.session.delete(self.SESSION_KEY)
            self.redirect(self.get_rooted_path("/"))


class TwitterOauthCallbackHandler(TwitterHandlerMixin,
                                  firenado.tornadoweb.TornadoHandler,
                                  TwitterMixin,DdossoHandlerMixin):
    @gen.coroutine
    @service.served_by("ddosso.services.SocialLinkService")
    def get(self):
        self.settings['twitter_consumer_key'] = self.component.conf[
            'social']['twitter']['key']
        self.settings['twitter_consumer_secret'] = self.component.conf[
            'social']['twitter']['secret']
        twitter_url_login = firenado.conf.app['login']['urls']['twitter']
        my_redirect_url = "%s://%s%s" % (self.request.protocol,
                                         self.request.host, twitter_url_login)

        if self.get_argument('oauth_token', False):
            user = yield self.get_authenticated_user()
            del user['description']
            del user['follow_request_sent']
            del user['status']
            del user['profile_link_color']
            del user['profile_text_color']
            del user['profile_sidebar_fill_color']
            del user['profile_sidebar_border_color']
            del user['profile_background_color']
            del user['statuses_count']
            user['oauth_token'] = self.get_argument('oauth_token')
            user['oauth_verifier'] = self.get_argument('oauth_verifier')
            # Save the user and access token with
            # e.g. set_secure_cookie.
            logger.info("User validated the twitter profile %s successfully." %
                        user['username'])
            self.session.set(self.SESSION_KEY, json_encode(user))
            self.redirect(self.get_rooted_path("twitter/oauth"))
        else:
            logger.info("User is trying to authenticate a twitter profile.")
            yield self.authorize_redirect(callback_uri=my_redirect_url)
                #extra_params={'approval_prompt': 'force'})
