#!/usr/bin/env python3
"""Lightweight local dashboard API for batch scan status + logs."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DEMO_STATUS = {
    "ok": True,
    "state": "running",
    "started_at": "2026-07-29T21:00:00+00:00",
    "updated_at": "2026-07-29T21:12:40+00:00",
    "finished_at": None,
    "input_dir": "apks",
    "output_dir": "results",
    "threads": 4,
    "progress": {"total": 100, "completed": 42, "succeeded": 40, "failed": 2, "percent": 42.0},
    "counts": {
        "findings": 128,
        "critical": 11,
        "high": 37,
        "has_aws": 3,
        "has_sendgrid": 1,
        "has_stripe": 2,
    },
    "current": ["org.example.app.apk", "com.demo.wallet.apk"],
    "jobs": [
        {
            "apk": "org.fdroid.fdroid.apk",
            "ok": True,
            "finding_count": 2,
            "has_critical": False,
            "duration_ms": 51200,
            "hits": {"aws": False, "sendgrid": False, "stripe": False},
        },
        {
            "apk": "com.demo.payments.apk",
            "ok": True,
            "finding_count": 5,
            "has_critical": True,
            "duration_ms": 78410,
            "hits": {"aws": True, "sendgrid": False, "stripe": True},
        },
    ],
    "logs": [
        {"ts": "2026-07-29T21:00:01+00:00", "level": "info", "message": "Discovered 100 APK(s); threads=4"},
        {"ts": "2026-07-29T21:05:12+00:00", "level": "info", "message": "Done org.fdroid.fdroid.apk: findings=2 ok=True (51200 ms)"},
        {"ts": "2026-07-29T21:08:44+00:00", "level": "info", "message": "Done com.demo.payments.apk: findings=5 ok=True (78410 ms)"},
        {"ts": "2026-07-29T21:10:02+00:00", "level": "error", "message": "Done broken.sample.apk: findings=0 ok=False (1200 ms)"},
    ],
}


class StatusHandler(BaseHTTPRequestHandler):
    status_path: Path = ROOT / "results" / "status.json"
    website_dist: Path = ROOT / "website" / "dist"

    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, code: int = 200) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"))

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/api/status", "/api/status.json"):
            if self.status_path.is_file():
                try:
                    data = json.loads(self.status_path.read_text(encoding="utf-8"))
                    self._json(data)
                    return
                except json.JSONDecodeError:
                    self._json({"ok": False, "error": "Invalid status JSON"}, 500)
                    return
            demo = dict(DEMO_STATUS)
            demo["demo"] = True
            self._json(demo)
            return

        if path == "/api/health":
            self._json({"ok": True, "status_path": str(self.status_path)})
            return

        # Optional static website preview from dist/
        if path == "/":
            path = "/index.html"
        candidate = (self.website_dist / path.lstrip("/")).resolve()
        if str(candidate).startswith(str(self.website_dist.resolve())) and candidate.is_file():
            ctype = "text/html"
            if candidate.suffix == ".js":
                ctype = "application/javascript"
            elif candidate.suffix == ".css":
                ctype = "text/css"
            elif candidate.suffix == ".json":
                ctype = "application/json"
            elif candidate.suffix in (".png", ".jpg", ".jpeg", ".webp", ".svg"):
                ctype = f"image/{candidate.suffix.lstrip('.').replace('svg', 'svg+xml')}"
            self._send(200, candidate.read_bytes(), ctype)
            return

        self._json({"ok": False, "error": "Not found", "paths": ["/api/status", "/api/health"]}, 404)

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve batch-scan status for the website dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--status",
        default=str(ROOT / "results" / "status.json"),
        help="Path to status.json written by tools/batch_scan.py",
    )
    args = parser.parse_args()

    StatusHandler.status_path = Path(args.status)
    server = ThreadingHTTPServer((args.host, args.port), StatusHandler)
    print(f"Dashboard API listening on http://{args.host}:{args.port}")
    print(f"Status file: {StatusHandler.status_path}")
    print("GET /api/status  |  GET /api/health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
