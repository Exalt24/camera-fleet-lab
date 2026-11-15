#!/usr/bin/env python3
"""A local stand-in for a chat or paging webhook, for the notify step of respond.py. It is not a real chat service: it accepts a
POST, appends the JSON body to a file and answers 200. --fail-first N answers 500 to the first N posts, to show the retry.

    python security/webhook_receiver.py --port 8765 --log security/state/received.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def make_handler(log: Path, fail_first: int):
    state = {"seen": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            size = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(size, 1_000_000))
            state["seen"] += 1
            if state["seen"] <= fail_first:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"ok": false}')
                return
            try:
                doc = json.loads(body)
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            log.parent.mkdir(parents=True, exist_ok=True)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(doc, sort_keys=True) + "\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

    return Handler


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--log", default=str(Path(__file__).resolve().parent / "state" / "received.jsonl"))
    p.add_argument("--fail-first", type=int, default=0)
    args = p.parse_args(argv)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(Path(args.log), args.fail_first))
    print(f"webhook receiver on http://127.0.0.1:{args.port}/notify (stand-in, logging to {args.log})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
