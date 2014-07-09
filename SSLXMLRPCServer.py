"""SSL XML-RPC Server.

This module provides SSL-enabled versions of ``SimpleXMLRPCServer``
and ``DocXMLRPCServer``.  Additionally, it also provides optional support for
HTTP Basic authentication and cross-origin resource sharing (CORS) requests.
No third-party libraries are required.

By default, authentication and CORS support is disabled in both the
``SSLSimpleXMLRPCServer`` and ``SSLDocXMLRPCServer`` classes.  To enable
authentication, create an instance of either server while passing an
authentication method via the ``auth_method`` keyword.  For example::

    def my_auth_function(server, username, password):
        if username == "joe":
            return True
        return False

    server = SSLSimpleXMLRPCServer(("localhost", 9000), "keyfile", "certfile",
                                   auth_method=my_auth_function)

If you are creating a subclass of ``SSLSimpleXMLRPCServer`` or
``SSLDocXMLRPCServer``, you can also just define a method named
``authentication``.  The following is functionally equivalent to the example
above::

    class MyServer(SSLSimpleXMLRPCServer):
        def authenticate(self, username, password):
            if username == "joe":
                return True
            return False

    server = MyServer(("localhost", 9000), "keyfile", "certfile")

To enable CORS, simply pass ``enable_cors=True`` to the class constructor.

Creating a threaded version is also really easy.  Simply use the
``SocketServer.ThreadingMixin`` mixin to create a server subclass, like so::

    import SocketServer

    class ThreadedSSLSimpleXMLRPCServer(SocketServer.ThreadingMixin,
                                        SSLSimpleXMLRPCServer):
        pass

"""

import base64
import DocXMLRPCServer
import SimpleXMLRPCServer
import ssl
import types

__all__ = ["AuthXMLRPCRequestHandlerMixin", "CORSXMLRPCRequestHandlerMixin",
           "SSLSimpleXMLRPCRequestHandler", "SSLDocXMLRPCRequestHandler",
           "SSLXMLRPCServerMixin",          "SSLSimpleXMLRPCServer",
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
            if not getattr(self.server, "require_auth", False):
                return True

            # Let OPTIONS requests go through without authentication
            if self.command == "OPTIONS":
                return True

            method, encoded = self.headers.get("Authorization", " ").split(" ")

            try:
                auth = base64.b64decode(encoded).split(":")
            except:
                # Invalid encoding
                auth = ""

            if len(auth) >= 2:
                username, password = auth[:2]
                if self.server.authenticate(username, password):
                    return True

            if self.command == "GET":
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Basic realm=\""+self.server.server_name+"\"")
                self.send_header("Content-type", "text/html")
                return True
            else:
                self.send_error(401, "Authentication failed")
                return False

        return False

class CORSXMLRPCRequestHandlerMixin:
    def end_headers(self):
        if getattr(self.server, "enable_cors", False):
            self.send_header("Access-Control-Allow-Origin",
                             self.headers.get('origin', '*'))
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.klass.end_headers(self)

    def do_OPTIONS(self):
        if getattr(self.server, "enable_cors", False):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Headers",
                             self.headers.get("Access-Control-Request-Headers", ""))
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()
        else:
            self.send_error(501, "Unsupported method (OPTIONS)")

class SSLSimpleXMLRPCRequestHandler(AuthXMLRPCRequestHandlerMixin,
                                    CORSXMLRPCRequestHandlerMixin,
                                    SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
    klass = SimpleXMLRPCServer.SimpleXMLRPCRequestHandler

class SSLDocXMLRPCRequestHandler(AuthXMLRPCRequestHandlerMixin,
                                 CORSXMLRPCRequestHandlerMixin,
                                 DocXMLRPCServer.DocXMLRPCRequestHandler):
    klass = DocXMLRPCServer.DocXMLRPCRequestHandler

class SSLXMLRPCServerMixin:
    def __init__(self, addr, keyfile, certfile,
                 auth_method=None, enable_cors=False, **kwargs):

        # If no ``requestHandler`` is supplied, use the default
        kwargs.setdefault("requestHandler", self.defaultRequestHandler)

        # Call superclass init
        self.klass.__init__(self, addr, **kwargs)

        # Check if there is an authentication method defined
        if callable(auth_method):
            # Bind the authentication method to this instance
            setattr(self, "authenticate", types.MethodType(auth_method, self))

        # Check if CORS support is requested
        self.enable_cors = enable_cors

        # Check to see if an ``authenticate`` method is defined
        self.require_auth = hasattr(self, 'authenticate') and \
                            callable(getattr(self, 'authenticate', None))

        # Finally, setup SSL
        self.socket = wrap_socket(self.socket, keyfile, certfile)


class SSLSimpleXMLRPCServer(SSLXMLRPCServerMixin,
                            SimpleXMLRPCServer.SimpleXMLRPCServer):

    klass                 = SimpleXMLRPCServer.SimpleXMLRPCServer
    defaultRequestHandler = SSLSimpleXMLRPCRequestHandler


class SSLDocXMLRPCServer(SSLXMLRPCServerMixin,
                         DocXMLRPCServer.DocXMLRPCServer):

    klass                 = DocXMLRPCServer.DocXMLRPCServer
    defaultRequestHandler = SSLDocXMLRPCRequestHandler

if __name__ == "__main__":
    def authenticate(server, username, password):
        """
        Simple auth function that only checks username.
        """
        if username == "admin":
            return True
        return False

    server = SSLDocXMLRPCServer(("localhost", 8001),
                                "privkey.pem", "cacert.pem",
                                auth_method=authenticate,
                                enable_cors=True)
                                
    server.register_introspection_functions()
    server.register_function(pow)
    server.serve_forever()
