import http.server
import socketserver

# Define the port you want to use
PORT = 8000
# Define the IP address you want to bind to
BIND_IP = "11.0.0.215"

# Create a request handler
Handler = http.server.SimpleHTTPRequestHandler

# Create a TCP server and bind it to the specified IP and port
with socketserver.TCPServer((BIND_IP, PORT), Handler) as httpd:
    print(f"Serving on http://{BIND_IP}:{PORT}")
    # Start the server