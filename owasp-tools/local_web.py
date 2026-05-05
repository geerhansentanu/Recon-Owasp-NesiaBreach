#!/usr/bin/env python3
"""
Local web UI untuk OWASP Rekon Aman.

Ini bukan server publik. Aplikasi hanya bind ke 127.0.0.1 supaya user bisa
input target dari browser lokal, lalu Python menjalankan scan di komputer user.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from owasp_recon import run_scan, write_html, write_json


APP_DIR = Path(__file__).resolve().parent
LOCAL_INDEX = APP_DIR / "local" / "index.html"
REPORT_HTML = APP_DIR / "report.html"
REPORT_JSON = APP_DIR / "report.json"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def response(handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class LocalHandler(BaseHTTPRequestHandler):
    server_version = "NesiaBreachLocal/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print("[local-web]", fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            response(self, 200, LOCAL_INDEX.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/report.html" and REPORT_HTML.exists():
            response(self, 200, REPORT_HTML.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/report.json" and REPORT_JSON.exists():
            response(self, 200, REPORT_JSON.read_bytes(), "application/json; charset=utf-8")
            return
        response(self, 404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/scan":
            response(self, 404, b'{"error":"Not found"}', "application/json; charset=utf-8")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            target = str(payload.get("target", "")).strip()
            timeout = float(payload.get("timeout", 10))
            skip_whois = bool(payload.get("skip_whois", False))
            insecure = bool(payload.get("insecure", False))
            if not target:
                raise ValueError("Target kosong")

            args = argparse.Namespace(
                target=target,
                out=str(REPORT_HTML),
                json_out=str(REPORT_JSON),
                scope_file=None,
                timeout=timeout,
                sitemap_limit=100,
                user_agent="OWASP Rekon Aman/1.0.0 local-ui NesiaBreach",
                skip_whois=skip_whois,
                insecure=insecure,
            )
            ctx = run_scan(args)
            write_json(ctx, str(REPORT_JSON))
            write_html(ctx, str(REPORT_HTML))

            data = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
            body = json.dumps(
                {
                    "ok": True,
                    "summary": {
                        "target": data.get("normalized_url"),
                        "final_url": data.get("http", {}).get("url"),
                        "http": data.get("http", {}).get("status_code"),
                        "findings": len(data.get("findings", [])),
                        "technologies": data.get("technologies", []),
                        "errors": data.get("errors", []),
                    },
                    "report_html": "/report.html",
                    "report_json": "/report.json",
                    "data": data,
                },
                ensure_ascii=False,
            ).encode("utf-8")
            response(self, 200, body, "application/json; charset=utf-8")
        except Exception as exc:  # noqa: BLE001
            body = json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False).encode("utf-8")
            response(self, 500, body, "application/json; charset=utf-8")


def main() -> int:
    port = find_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), LocalHandler)
    url = f"http://127.0.0.1:{port}/"
    print("OWASP Rekon Aman // NesiaBreach")
    print(f"Local UI: {url}")
    print("Tutup terminal ini untuk menghentikan aplikasi.")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDihentikan.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
