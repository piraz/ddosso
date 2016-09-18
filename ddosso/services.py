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
from firenado.config import load_yaml_config_file
from .diaspora.models import PersonBase, ProfileBase, UserBase
from passlib.hash import bcrypt
import datetime
import os


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

    def is_password_valid(self, challenge, encrypted_password):
        return bcrypt.verify(
            self.get_peppered_password(challenge), encrypted_password)

    def get_peppered_password(self, password):
        ddosso_conf = load_yaml_config_file(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'conf', 'ddosso.yml'))
        return '%s%s' % (password, ddosso_conf['diaspora']['password']['pepper'])


class PersonService(service.FirenadoService):

    def by_user(self, user):
        db_session = self.get_data_source('diaspora').session
        return db_session.query(PersonBase).filter(
            PersonBase.owner_id == user.id).one_or_none()
        db_session.close()


class ProfileService(service.FirenadoService):

    def by_person(self, person):
        db_session = self.get_data_source('diaspora').session
        return db_session.query(ProfileBase).filter(
            ProfileBase.person_id == person.id).one_or_none()
        db_session.close()


class LoginService(service.FirenadoService):

    def __init__(self, handler, data_source=None):
        service.FirenadoService.__init__(self, handler, data_source)

    @service.served_by("ddosso.services.PersonService")
    @service.served_by("ddosso.services.ProfileService")
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

        if user:
            people = self.person_service.by_user(user)
            profile = self.profile_service.by_person(people)

            user_name = None
            if profile.full_name != "":
                user_name = profile.full_name
            elif profile.first_name != "":
                if profile.last_name != "":
                    user_name = "%s %s" % (
                    profile.first_name, profile.last_name)
                else:
                    user_name = profile.first_name
            else:
                user_name = user.username

            user_data = {
                "id": 0,
                "username": "",
                "email": "",
                "guid": "",
                "name": "",
                "avatar": "",
            }
            if self.user_service.is_password_valid(password,
                    user.encrypted_password):
                user_data['id'] = user.id
                user_data['username'] = user.username
                user_data['email'] = user.email
                user_data['guid'] = people.guid
                user_data['name'] = user_name.title()
                user_data['avatar'] = profile.image_url_medium
                return user_data
        return False
