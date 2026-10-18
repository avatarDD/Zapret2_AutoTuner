#!/usr/bin/env python3
"""Test web server of the DPI stand (docs/PLAN.md §6): HTTPS on 443 and HTTP on 80, all addresses.

GET /       small page (2 KB)
GET /big    600 KB body (full-download checks, the 16 KB cut-off)
Host redirect.test on port 80 answers 302 to a foreign domain, like an ISP block page.
"""
import http.server
import socketserver
import ssl
import sys
import threading

BIG = b"z" * 600_000
SMALL = b"<html>" + b"s" * 2000 + b"</html>"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, head_only):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host == "redirect.test" and not isinstance(self.connection, ssl.SSLSocket):
            self.send_response(302)
            self.send_header("Location", "http://warning.rt.ru/?id=17")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        body = BIG if self.path.startswith("/big") else SMALL
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_GET(self):
        self._send(False)

    def do_HEAD(self):
        self._send(True)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    cert, key = sys.argv[1], sys.argv[2]
    https = Server(("0.0.0.0", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    https.socket = ctx.wrap_socket(https.socket, server_side=True, do_handshake_on_connect=False)
    plain = Server(("0.0.0.0", 80), Handler)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    print("ready", flush=True)
    https.serve_forever()


if __name__ == "__main__":
    main()
