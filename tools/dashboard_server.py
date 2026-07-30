#!/usr/bin/env python3
"""Dashboard API: status, system stats, download/thread controls, raw results export."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from results_format import aggregate_results  # noqa: E402

APKS_DIR = ROOT / "apks"
RESULTS_DIR = ROOT / "results"
CONFIG_PATH = RESULTS_DIR / "dashboard-config.json"
DOWNLOAD_STATUS_PATH = RESULTS_DIR / "download-status.json"

_STATE_LOCK = threading.Lock()
_DOWNLOAD_PROC: subprocess.Popen | None = None
_SCAN_PROC: subprocess.Popen | None = None
_PREV_CPU: tuple[int, int] | None = None


DEMO_STATUS = {
    "ok": True,
    "demo": True,
    "state": "running",
    "started_at": "2026-07-29T21:00:00+00:00",
    "updated_at": "2026-07-29T21:12:40+00:00",
    "finished_at": None,
    "input_dir": "apks",
    "output_dir": "results",
    "threads": 4,
    "progress": {"total": 100, "completed": 42, "succeeded": 40, "failed": 2, "percent": 42.0},
    "counts": {
        "findings": 3,
        "critical": 1,
        "high": 2,
        "has_aws": 1,
        "has_sendgrid": 0,
        "has_stripe": 1,
    },
    "current": ["org.example.app.apk", "com.demo.wallet.apk"],
    "active": {
        "org.example.app.apk": {
            "apk": "org.example.app.apk",
            "phase": "decompiling",
            "percent": 45,
            "message": "Decompiling with jadx (this can take a while)",
            "elapsed_ms": 18200,
            "started_at": "2026-07-29T21:10:00+00:00",
        },
        "com.demo.wallet.apk": {
            "apk": "com.demo.wallet.apk",
            "phase": "scanning",
            "percent": 78,
            "message": "Matching secret patterns",
            "elapsed_ms": 9400,
            "started_at": "2026-07-29T21:11:00+00:00",
        },
    },
    "jobs": [],
    "logs": [
        {"ts": "2026-07-29T21:00:01+00:00", "level": "info", "message": "Discovered 100 APK(s); threads=4"},
    ],
    "raw_lines": [
        "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "example_payment_token_not_real",
        "example_mail_token_not_real",
    ],
    "priority_lines": [
        "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
    "other_lines": [
        "example_payment_token_not_real",
        "example_mail_token_not_real",
    ],
    "aws_pairs": [
        "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
}


def _default_config() -> dict:
    return {
        "threads": 4,
        "download_count": 100,
        "severity": "high",
        "apks_dir": str(APKS_DIR),
        "results_dir": str(RESULTS_DIR),
    }


def load_config() -> dict:
    cfg = _default_config()
    if CONFIG_PATH.is_file():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg.update(data)
        except json.JSONDecodeError:
            pass
    cfg["threads"] = max(1, min(32, int(cfg.get("threads") or 4)))
    cfg["download_count"] = max(1, min(5000, int(cfg.get("download_count") or 100)))
    return cfg


def save_config(cfg: dict) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    merged = load_config()
    merged.update(cfg)
    merged["threads"] = max(1, min(32, int(merged.get("threads") or 4)))
    merged["download_count"] = max(1, min(5000, int(merged.get("download_count") or 100)))
    CONFIG_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def _read_cpu_times() -> tuple[int, int]:
    # /proc/stat: cpu user nice system idle iowait irq softirq ...
    line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
    parts = line.split()
    vals = [int(x) for x in parts[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)
    return idle, total


def system_stats() -> dict:
    global _PREV_CPU
    meminfo = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        num = rest.strip().split()[0]
        try:
            meminfo[key] = int(num)  # kB
        except ValueError:
            continue
    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
    mem_used = max(0, mem_total - mem_available)
    mem_percent = round(100.0 * mem_used / mem_total, 1) if mem_total else 0.0

    idle, total = _read_cpu_times()
    cpu_percent = 0.0
    if _PREV_CPU is not None:
        prev_idle, prev_total = _PREV_CPU
        d_idle = idle - prev_idle
        d_total = total - prev_total
        if d_total > 0:
            cpu_percent = round(100.0 * (1.0 - (d_idle / d_total)), 1)
    _PREV_CPU = (idle, total)

    loadavg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    apk_count = len(list(APKS_DIR.glob("*.apk"))) if APKS_DIR.is_dir() else 0

    with _STATE_LOCK:
        download_running = _DOWNLOAD_PROC is not None and _DOWNLOAD_PROC.poll() is None
        scan_running = _SCAN_PROC is not None and _SCAN_PROC.poll() is None

    return {
        "ok": True,
        "cpu_percent": cpu_percent,
        "memory": {
            "total_kb": mem_total,
            "used_kb": mem_used,
            "available_kb": mem_available,
            "percent": mem_percent,
            "total_gb": round(mem_total / (1024 * 1024), 2),
            "used_gb": round(mem_used / (1024 * 1024), 2),
        },
        "loadavg": list(loadavg),
        "apk_count": apk_count,
        "download_running": download_running,
        "scan_running": scan_running,
        "config": load_config(),
    }


def _write_download_status(payload: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_STATUS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def start_download(count: int) -> dict:
    global _DOWNLOAD_PROC
    cfg = save_config({"download_count": count})
    with _STATE_LOCK:
        if _DOWNLOAD_PROC is not None and _DOWNLOAD_PROC.poll() is None:
            return {"ok": False, "error": "Download already running", "error_code": "BUSY"}
        APKS_DIR.mkdir(parents=True, exist_ok=True)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = ROOT / "logs" / "fdroid_download.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        _write_download_status({
            "ok": True,
            "state": "starting",
            "requested": count,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        venv_python = ROOT / ".venv" / "bin" / "python3"
        python = str(venv_python) if venv_python.is_file() else sys.executable
        cmd = [
            python,
            str(TOOLS / "fdroid_download.py"),
            "-n",
            str(count),
            "-o",
            str(APKS_DIR),
        ]
        log_fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
        _DOWNLOAD_PROC = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        proc = _DOWNLOAD_PROC

    def _watch() -> None:
        code = proc.wait()
        _write_download_status({
            "ok": code == 0,
            "state": "completed" if code == 0 else "failed",
            "requested": count,
            "exit_code": code,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "apk_count": len(list(APKS_DIR.glob("*.apk"))) if APKS_DIR.is_dir() else 0,
        })

    threading.Thread(target=_watch, daemon=True).start()
    return {
        "ok": True,
        "state": "started",
        "requested": count,
        "pid": proc.pid,
        "config": cfg,
        "message": f"Downloading {count} new APKs (skipping duplicates)",
    }


def start_scan(threads: int | None = None) -> dict:
    global _SCAN_PROC
    cfg = save_config({"threads": threads} if threads is not None else {})
    threads_n = int(cfg["threads"])
    with _STATE_LOCK:
        if _SCAN_PROC is not None and _SCAN_PROC.poll() is None:
            try:
                os.killpg(os.getpgid(_SCAN_PROC.pid), 15)
            except OSError:
                try:
                    _SCAN_PROC.terminate()
                except OSError:
                    pass
            try:
                _SCAN_PROC.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    _SCAN_PROC.kill()
                except OSError:
                    pass

        APKS_DIR.mkdir(parents=True, exist_ok=True)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = ROOT / "logs" / "batch_scan.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        venv_python = ROOT / ".venv" / "bin" / "python3"
        python = str(venv_python) if venv_python.is_file() else sys.executable
        cmd = [
            python,
            str(TOOLS / "batch_scan.py"),
            "-d",
            str(APKS_DIR),
            "-t",
            str(threads_n),
            "-o",
            str(RESULTS_DIR),
            "-s",
            str(cfg.get("severity") or "high"),
            "--status",
            str(RESULTS_DIR / "status.json"),
        ]
        log_fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
        _SCAN_PROC = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        proc = _SCAN_PROC
    return {
        "ok": True,
        "state": "started",
        "threads": threads_n,
        "pid": proc.pid,
        "config": cfg,
        "message": f"Batch scan started with {threads_n} threads",
    }


def _iter_result_jobs(status_jobs: list | None = None) -> list[dict]:
    """Merge status jobs with on-disk per-APK JSON (prefer full findings)."""
    jobs: list[dict] = list(status_jobs or [])
    if RESULTS_DIR.is_dir():
        for path in RESULTS_DIR.glob("*.json"):
            if path.name in {
                "status.json",
                "summary.json",
                "dashboard-config.json",
                "download-status.json",
            }:
                continue
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(job, dict) and job.get("apk"):
                jobs.append(job)
    by_name: dict[str, dict] = {}
    for job in jobs:
        name = job.get("apk") or ""
        if not name:
            continue
        prev = by_name.get(name)
        if prev is None:
            by_name[name] = job
            continue
        prev_has = bool(prev.get("findings") or prev.get("results"))
        cur_has = bool(job.get("findings") or job.get("results"))
        prev_pri = len(prev.get("priority_lines") or []) + len(prev.get("other_lines") or [])
        cur_pri = len(job.get("priority_lines") or []) + len(job.get("other_lines") or [])
        if cur_has and not prev_has:
            by_name[name] = job
        elif cur_has == prev_has and cur_pri > prev_pri:
            by_name[name] = job
    return list(by_name.values())


def load_status(status_path: Path) -> dict:
    if status_path.is_file():
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Always merge disk per-APK files so Priority/Other do not vanish
                # when a new scan rewrites status.json with an empty jobs list.
                agg = aggregate_results(_iter_result_jobs(data.get("jobs") or []))
                data["raw_lines"] = agg["lines"]
                data["priority_lines"] = agg.get("priority_lines") or []
                data["other_lines"] = agg.get("other_lines") or []
                data["aws_pairs"] = agg["aws_pairs"]
                data["counts"] = data.get("counts") or {}
                data["counts"]["findings"] = len(agg["lines"])
                data["counts"]["has_aws"] = len(agg["aws_pairs"])
                data["demo"] = False
                return data
        except json.JSONDecodeError:
            return {"ok": False, "error": "Invalid status JSON", "demo": False}
    demo = dict(DEMO_STATUS)
    return demo


def collect_results(status_path: Path) -> dict:
    status = load_status(status_path)
    jobs = _iter_result_jobs(status.get("jobs") or [])
    agg = aggregate_results(jobs)
    agg["total"] = len(agg.get("lines") or [])
    agg["priority_total"] = len(agg.get("priority_lines") or [])
    agg["other_total"] = len(agg.get("other_lines") or [])
    agg["text"] = "\n".join(agg.get("lines") or []) + ("\n" if agg.get("lines") else "")
    agg["priority_text"] = "\n".join(agg.get("priority_lines") or []) + (
        "\n" if agg.get("priority_lines") else ""
    )
    agg["other_text"] = "\n".join(agg.get("other_lines") or []) + (
        "\n" if agg.get("other_lines") else ""
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "results.txt").write_text(agg["text"], encoding="utf-8")
    (RESULTS_DIR / "priority-results.txt").write_text(agg["priority_text"], encoding="utf-8")
    (RESULTS_DIR / "other-results.txt").write_text(agg["other_text"], encoding="utf-8")
    return agg


class StatusHandler(BaseHTTPRequestHandler):
    status_path: Path = RESULTS_DIR / "status.json"
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

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _content_type(self, path: Path) -> str:
        if path.suffix == ".js":
            return "application/javascript"
        if path.suffix == ".css":
            return "text/css"
        if path.suffix == ".json":
            return "application/json"
        if path.suffix == ".html":
            return "text/html; charset=utf-8"
        if path.suffix in (".png", ".jpg", ".jpeg", ".webp", ".svg"):
            return f"image/{path.suffix.lstrip('.').replace('svg', 'svg+xml')}"
        if path.suffix == ".ico":
            return "image/x-icon"
        if path.suffix == ".txt":
            return "text/plain; charset=utf-8"
        return "application/octet-stream"

    def _serve_file(self, candidate: Path) -> bool:
        dist_root = self.website_dist.resolve()
        try:
            resolved = candidate.resolve()
        except OSError:
            return False
        if not str(resolved).startswith(str(dist_root)) or not resolved.is_file():
            return False
        self._send(200, resolved.read_bytes(), self._content_type(resolved))
        return True

    def _serve_spa(self, rel_path: str) -> bool:
        if not self.website_dist.is_dir():
            return False
        rel = rel_path.lstrip("/")
        if not rel or rel.endswith("/"):
            rel = (rel + "index.html") if rel else "index.html"
        if self._serve_file(self.website_dist / rel):
            return True
        if "." not in Path(rel).name:
            return self._serve_file(self.website_dist / "index.html")
        return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/api/status", "/api/status.json"):
            data = load_status(self.status_path)
            data["system"] = system_stats()
            data["config"] = load_config()
            self._json(data)
            return

        if path == "/api/health":
            self._json({"ok": True, "status_path": str(self.status_path)})
            return

        if path == "/api/system":
            self._json(system_stats())
            return

        if path == "/api/config":
            self._json({"ok": True, "config": load_config()})
            return

        if path in ("/api/results", "/api/results.json"):
            self._json(collect_results(self.status_path))
            return

        if path in ("/api/results.txt", "/api/export.txt"):
            agg = collect_results(self.status_path)
            self._send(200, agg["text"].encode("utf-8"), "text/plain; charset=utf-8")
            return

        if path in ("/api/results/priority.txt", "/api/export/priority.txt"):
            agg = collect_results(self.status_path)
            self._send(200, agg.get("priority_text", "").encode("utf-8"), "text/plain; charset=utf-8")
            return

        if path in ("/api/results/other.txt", "/api/export/other.txt"):
            agg = collect_results(self.status_path)
            self._send(200, agg.get("other_text", "").encode("utf-8"), "text/plain; charset=utf-8")
            return

        if path == "/api/download/status":
            if DOWNLOAD_STATUS_PATH.is_file():
                try:
                    self._json(json.loads(DOWNLOAD_STATUS_PATH.read_text(encoding="utf-8")))
                    return
                except json.JSONDecodeError:
                    pass
            with _STATE_LOCK:
                running = _DOWNLOAD_PROC is not None and _DOWNLOAD_PROC.poll() is None
            self._json({"ok": True, "state": "running" if running else "idle"})
            return

        site_prefix = "/apkleaks-skills"
        if path == site_prefix or path.startswith(site_prefix + "/"):
            rel = path[len(site_prefix) :] or "/"
            if self._serve_spa(rel):
                return
        if path in ("/", "/dashboard", "/features", "/skills", "/install"):
            target = f"{site_prefix}/dashboard" if path != "/" else f"{site_prefix}/dashboard"
            if path == "/":
                target = f"{site_prefix}/dashboard"
            body = (
                f'<html><head><meta http-equiv="refresh" content="0;url={target}"></head>'
                f'<body><a href="{target}">{target}</a></body></html>'
            ).encode()
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        if self._serve_spa(path):
            return

        self._json(
            {
                "ok": False,
                "error": "Not found",
                "paths": [
                    "/api/status",
                    "/api/system",
                    "/api/results",
                    "/api/results.txt",
                    "/api/download",
                    "/api/threads",
                    "/apkleaks-skills/dashboard",
                ],
            },
            404,
        )

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        body = self._read_json_body()

        if path in ("/api/download", "/api/download/start"):
            count = body.get("count", load_config().get("download_count", 100))
            try:
                count = int(count)
            except (TypeError, ValueError):
                self._json({"ok": False, "error": "count must be an integer"}, 400)
                return
            if count < 1:
                self._json({"ok": False, "error": "count must be >= 1"}, 400)
                return
            self._json(start_download(count))
            return

        if path in ("/api/threads", "/api/scan/start"):
            threads = body.get("threads", load_config().get("threads", 4))
            try:
                threads = int(threads)
            except (TypeError, ValueError):
                self._json({"ok": False, "error": "threads must be an integer"}, 400)
                return
            if threads < 1 or threads > 32:
                self._json({"ok": False, "error": "threads must be 1..32"}, 400)
                return
            restart = bool(body.get("restart", True))
            cfg = save_config({"threads": threads})
            if restart:
                result = start_scan(threads)
                self._json(result)
            else:
                self._json({"ok": True, "config": cfg, "message": "Threads saved (scan not restarted)"})
            return

        if path == "/api/config":
            cfg = save_config(body)
            self._json({"ok": True, "config": cfg})
            return

        self._json({"ok": False, "error": "Not found"}, 404)

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve batch-scan dashboard API + UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--status",
        default=str(RESULTS_DIR / "status.json"),
        help="Path to status.json written by tools/batch_scan.py",
    )
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    save_config(load_config())  # ensure config exists
    # Prime CPU percent baseline
    system_stats()
    time.sleep(0.15)
    system_stats()

    StatusHandler.status_path = Path(args.status)
    server = ThreadingHTTPServer((args.host, args.port), StatusHandler)
    print(f"Dashboard API listening on http://{args.host}:{args.port}")
    print(f"Status file: {StatusHandler.status_path}")
    print("GET /api/status /api/system /api/results /api/results.txt")
    print("POST /api/download  /api/threads")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
