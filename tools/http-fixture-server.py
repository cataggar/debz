#!/usr/bin/env python3
"""Serve a local hermetic fixture tree and record redacted request paths."""

from __future__ import annotations

import argparse
import http.server
import pathlib
import urllib.parse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--port-file", required=True, type=pathlib.Path)
    parser.add_argument("--request-log", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.root.is_absolute() or not args.port_file.is_absolute() or not args.request_log.is_absolute():
        raise SystemExit("fixture paths must be absolute")

    root = args.root.resolve(strict=True)
    request_log = args.request_log

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=str(root), **handler_kwargs)

        def log_message(self, format: str, *values: object) -> None:
            del format, values
            path = urllib.parse.urlsplit(self.path).path
            with request_log.open("a", encoding="utf-8") as stream:
                stream.write(path + "\n")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    args.port_file.write_text(f"{server.server_port}\n", encoding="ascii")
    server.serve_forever()


if __name__ == "__main__":
    main()
