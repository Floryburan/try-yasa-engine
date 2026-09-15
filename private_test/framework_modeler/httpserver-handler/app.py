from http.server import BaseHTTPRequestHandler, HTTPServer


class ApiHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        request_path = self.path
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body + request_path.encode())


server = HTTPServer(("127.0.0.1", 8000), ApiHandler)
server.serve_forever()

