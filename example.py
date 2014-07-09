from SSLXMLRPCServer import SSLDocXMLRPCServer

import math

if __name__ == "__main__":
    server = SSLDocXMLRPCServer(("localhost", 9000),
                                "privkey.pem", "cacert.pem",
                                enable_cors=True)

    # Make all functions in math accessible
    for meth in [getattr(math, attr) for attr in dir(math) if attr.islower()]:
        if callable(meth) and hasattr(meth, "__name__"):
            server.register_function(meth)

    print "Open https://localhost:9000/ in a browser to see available methods"
    server.serve_forever()
