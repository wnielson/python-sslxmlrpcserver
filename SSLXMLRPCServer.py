"""SSL XML-RPC Server.

This module provides SSL-enabled versions of ``SimpleXMLRPCServer``
and ``DocXMLRPCServer``.  Additionally, it also provides optional support for
HTTP Basic authentication and cross-origin resource sharing (CORS) requests.
No third-party libraries are required.

"""

import base64
import DocXMLRPCServer
import SimpleXMLRPCServer
import ssl

__all__ = ["AuthXMLRPCRequestHandlerMixin", "CORSXMLRPCRequestHandlerMixin",
           "SSLSimpleXMLRPCRequestHandler", "SSLDocXMLRPCRequestHandler",
           "AuthXMLRPCServerMixin", "SSLSimpleXMLRPCServer",
           "SSLDocXMLRPCServer"]

def wrap_socket(socket, keyfile, certfile):
    return ssl.wrap_socket(socket,
                           keyfile,
                           certfile,
                           server_side=True,
                           ssl_version=ssl.PROTOCOL_SSLv23)

class AuthXMLRPCRequestHandlerMixin:
    def parse_request(self):
        if self.klass.parse_request(self):
            method, encoded = self.headers.get("Authorization", " ").split(" ")
            auth = base64.b64decode(encoded).split(":")

            if len(auth) >= 2:
                username, password = auth[:2]
                if self.server.authenticate(username, password):
                    return True

            if self.command == "GET":
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm=\"'+self.server.server_name+'\"')
                self.send_header('Content-type', 'text/html')
                return True
            else:
                self.send_error(401, 'Authentication failed')
                return False

class CORSXMLRPCRequestHandlerMixin:
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin",
                         self.headers.get('origin', '*'))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.klass.end_headers(self)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Headers",
                         self.headers.get("Access-Control-Request-Headers", ""))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

class SSLSimpleXMLRPCRequestHandler(AuthXMLRPCRequestHandlerMixin,
                                    CORSXMLRPCRequestHandlerMixin,
                                    SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
    klass = SimpleXMLRPCServer.SimpleXMLRPCRequestHandler

class SSLDocXMLRPCRequestHandler(AuthXMLRPCRequestHandlerMixin,
                                 CORSXMLRPCRequestHandlerMixin,
                                 DocXMLRPCServer.DocXMLRPCRequestHandler):
    klass = DocXMLRPCServer.DocXMLRPCRequestHandler


class AuthXMLRPCServerMixin:
    def authenticate(self, username, password):
        """
        Override this method to provide your own authentication method.
        """
        return True


class SSLSimpleXMLRPCServer(AuthXMLRPCServerMixin,
                            SimpleXMLRPCServer.SimpleXMLRPCServer):
    def __init__(self, addr, keyfile, certfile, **kwargs):
        kwargs.setdefault("requestHandler", SSLSimpleXMLRPCRequestHandler)

        SimpleXMLRPCServer.SimpleXMLRPCServer.__init__(self, addr, **kwargs)

        self.socket = wrap_socket(self.socket, keyfile, certfile)


class SSLDocXMLRPCServer(AuthXMLRPCServerMixin,
                         DocXMLRPCServer.DocXMLRPCServer):
    def __init__(self, addr, keyfile, certfile, **kwargs):
        kwargs.setdefault("requestHandler", SSLDocXMLRPCRequestHandler)

        DocXMLRPCServer.DocXMLRPCServer.__init__(self, addr, **kwargs)

        self.socket = wrap_socket(self.socket, keyfile, certfile)

if __name__ == "__main__":
    class Server(SSLDocXMLRPCServer):
        def authenticate(self, username, password):
            if username == "admin":
                return True
            return False

    server = Server(("localhost", 8001), "privkey.pem", "cacert.pem")
    server.register_introspection_functions()
    server.register_function(pow)
    server.serve_forever()
