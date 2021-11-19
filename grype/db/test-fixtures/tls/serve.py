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
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='server.key', certfile="server.crt", server_side=True)

print(f"Server running on https://0.0.0.0:{port}")
httpd.serve_forever()