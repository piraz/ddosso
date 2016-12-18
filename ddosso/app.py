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

from . import handlers
from . import uimodules
from .rabbitmq import RabbitMQClient
from .util import rooted_path

import firenado.conf
from firenado.config import load_yaml_config_file
import firenado.tornadoweb
import logging
import os

logger = logging.getLogger(__name__)


class DDOSSOComponent(firenado.tornadoweb.TornadoComponent):

    def __init__(self, name, application):
        super(DDOSSOComponent, self).__init__(name, application)
        self.rabbitmq = {'client': None}

    def get_handlers(self):
        self.conf['social']['enabled'] = False
        if (self.conf['social']['facebook']['enabled'] or
                self.conf['social']['google']['enabled'] or
                self.conf['social']['twitter']['enabled']):
            self.conf['social']['enabled'] = True
        root = self.conf['root']
        return [
            (r"%s" % rooted_path(root, "/"), handlers.IndexHandler),
            (r"%s" % rooted_path(root, "/captcha/(.*)"),
             handlers.CaptchaHandler),
            (r"%s" % rooted_path(root, "/profile"), handlers.ProfileHandler),
            (r"%s" % rooted_path(root, "/profile/diaspora"),
             handlers.DiasporaProfileHandler),
            (r"%s" % rooted_path(root, "/sign_in"), handlers.SigninHandler),
            (r"%s" % rooted_path(root, "/sign_up"), handlers.SignupHandler),
            (r"%s" % rooted_path(root, "/social/(.*)"), handlers.SocialHandler),
        ]

    def get_ui_modules(self):
        return uimodules

    def get_config_file(self):
        return "ddosso"

    def initialize(self):
        self.conf['diaspora']['domain'] = self.conf['diaspora'][
            'url'].replace("https://", "").replace("http://", "")
        self.rabbitmq['client'] = RabbitMQClient(
            load_yaml_config_file(os.path.join(firenado.conf.APP_CONFIG_PATH,
                                               'rabbitmq.yml')))
        self.rabbitmq['client'].connect()

    def shutdown(self):
        self.rabbitmq['client'].disconnect()

    def install(self):
        from sqlalchemy import text
        from firenado.util.sqlalchemy_util import Base
        from .diaspora.models import DddossoSocialLinkBase
        print('Installing DDOSSO...')
        print('Creating DDOSSO users table ...')
        engine = self.application.get_data_source(
            'diaspora').engine
        engine.echo = False
        # Dropping all
        # TODO Not to drop all if something is installed right?

        DddossoSocialLinkBase.__table__.drop(engine, checkfirst=True)
        # Creating database
        DddossoSocialLinkBase.__table__.create(engine)
        engine.dispose()
