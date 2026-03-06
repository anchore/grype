from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import logging

port = 443
directory = "www"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        logging.error(self.headers)
        SimpleHTTPRequestHandler.do_GET(self)


httpd = HTTPServer(('0.0.0.0', port), Handler)
sslctx = ssl.SSLContext()
sslctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
sslctx.load_cert_chain(certfile='server.crt', keyfile="server.key")
httpd.socket = sslctx.wrap_socket(httpd.socket, server_side=True)

print(f"Server running on https://0.0.0.0:{port}")
httpd.serve_forever()