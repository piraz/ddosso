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

from firenado import service
from .diaspora.models import UserBase
import datetime


def password_digest(pass_phrase):
    import hashlib
    m = hashlib.md5()
    m.update(pass_phrase.encode('utf-8'))
    return m.hexdigest()


class UserService(service.FirenadoService):

    def by_username(self, username):
        db_session = self.get_data_source('diaspora').session
        return db_session.query(UserBase).filter(
            UserBase.username == username).one_or_none()
        db_session.close()


class LoginService(service.FirenadoService):

    def __init__(self, handler, data_source=None):
        service.FirenadoService.__init__(self, handler, data_source)

    @service.served_by("ddosso.services.UserService")
    def is_valid(self, username, password):
        """ Checks if challenge username and password matches
        username and password defined on the service constructor..

        Args:
            username: A challenge username
            password: A challenge password

        Returns: Returns true if challenge username and password matches
        username and password defined on the service constructor.

        """
        user = self.user_service.by_username(username)
        print(user)
        if user:
            if user.encrypted_password == password_digest(password):
                return True
        return False
