from . import handlers
import firenado.tornadoweb


class DDOSSOComponent(firenado.tornadoweb.TornadoComponent):

    def get_handlers(self):
        return [
            (r'/', handlers.IndexHandler),
        ]
