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

import firenado.tornadoweb
from ddosso.util import rooted_path


class FacebookComponent(firenado.tornadoweb.TornadoComponent):

    def get_handlers(self):
        root = self.conf['root']
        return [
            (r"%s" % rooted_path(root, "facebook/authorize"),
             handlers.FacebookRouterHandler),
            (r"%s" % rooted_path(root, "facebook/graph_auth"),
             handlers.FacebookGraphAuthHandler),
        ]

    def get_config_file(self):
        return "ddosso"
