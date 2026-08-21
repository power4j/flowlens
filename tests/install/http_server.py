#!/usr/bin/env python3
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer, ThreadingMixIn
import os


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    # Use TCPServer instead of HTTPServer to avoid socket.getfqdn() during bind.
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--mode", default="ok")
    parser.add_argument("--port-file")
    parser.add_argument("--pid-file")
    args = parser.parse_args()
    root = Path(args.root)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if args.mode == "404" or path == "/force-404":
                self._send(404, b"not found", "text/plain")
                return
            if args.mode == "403" or path == "/force-403" or (root / "force_403").exists():
                self.send_response(403)
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("X-RateLimit-Reset", "4102444800")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"rate limited")
                return
            if path.endswith("/releases/latest"):
                target = root / "latest.json"
            elif "/releases/download/" in path:
                parts = [part for part in path.split("/") if part]
                target = root / parts[-2] / parts[-1]
            else:
                target = None
            if target is None or not target.is_file():
                self._send(404, b"not found", "text/plain")
                return
            data = target.read_bytes()
            content_type = "application/json" if target.suffix == ".json" else "application/octet-stream"
            self._send(200, data, content_type)

        def _send(self, code, body, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *log_args):
            return

    server = ThreadingTCPServer(("127.0.0.1", args.port), Handler)
    port = server.server_address[1]
    if args.port_file:
        Path(args.port_file).write_text(str(port) + "\n", encoding="utf-8")
    if args.pid_file:
        Path(args.pid_file).write_text(str(os.getpid()) + "\n", encoding="utf-8")
    print(port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
