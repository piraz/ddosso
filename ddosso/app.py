from . import handlers
import firenado.tornadoweb


class DDOSSOComponent(firenado.tornadoweb.TornadoComponent):

    def get_handlers(self):
        return [
            (r'/', handlers.IndexHandler),
            (r'/sso_login', handlers.IndexHandler),
        ]

    def get_config_file(self):
        return "ddosso"
