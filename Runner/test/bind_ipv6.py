from http.server import HTTPServer
from http.server import SimpleHTTPRequestHandler
import socket

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

server = HTTPServerV6(('::', 8081), SimpleHTTPRequestHandler)
server.serve_forever()