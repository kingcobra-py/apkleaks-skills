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
LOOP_STATUS_PATH = RESULTS_DIR / "loop-status.json"

_STATE_LOCK = threading.RLock()
_DOWNLOAD_PROC: subprocess.Popen | None = None
_SCAN_PROC: subprocess.Popen | None = None
_PREV_CPU: tuple[int, int] | None = None
_RESULTS_CACHE: dict = {"key": None, "agg": None, "built_at": 0.0}
_SYSTEM_CACHE: dict = {"built_at": 0.0, "data": None}
_LOOP_STOP = threading.Event()
_LOOP_THREAD: threading.Thread | None = None
_META_SKIP = {
    "status.json",
    "summary.json",
    "dashboard-config.json",
    "download-status.json",
    "loop-status.json",
}


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
        "download_workers": 10,
        "loop_enabled": False,
        "loop_apps": 100,
        "loop_threads": 12,
        "loop_download_workers": 10,
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
    cfg["download_workers"] = max(1, min(32, int(cfg.get("download_workers") or 10)))
    cfg["loop_apps"] = max(1, min(5000, int(cfg.get("loop_apps") or 100)))
    cfg["loop_threads"] = max(1, min(32, int(cfg.get("loop_threads") or cfg["threads"])))
    cfg["loop_download_workers"] = max(
        1, min(32, int(cfg.get("loop_download_workers") or cfg["download_workers"]))
    )
    cfg["loop_enabled"] = bool(cfg.get("loop_enabled"))
    return cfg


def save_config(cfg: dict) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    merged = load_config()
    merged.update(cfg)
    merged["threads"] = max(1, min(32, int(merged.get("threads") or 4)))
    merged["download_count"] = max(1, min(5000, int(merged.get("download_count") or 100)))
    merged["download_workers"] = max(1, min(32, int(merged.get("download_workers") or 10)))
    merged["loop_apps"] = max(1, min(5000, int(merged.get("loop_apps") or 100)))
    merged["loop_threads"] = max(1, min(32, int(merged.get("loop_threads") or merged["threads"])))
    merged["loop_download_workers"] = max(
        1, min(32, int(merged.get("loop_download_workers") or merged["download_workers"]))
    )
    merged["loop_enabled"] = bool(merged.get("loop_enabled"))
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


def system_stats(force: bool = False) -> dict:
    global _PREV_CPU
    now = time.time()
    cached = _SYSTEM_CACHE.get("data")
    if (
        not force
        and cached is not None
        and (now - float(_SYSTEM_CACHE.get("built_at") or 0)) < 1.5
    ):
        return cached

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
        loop_running = _LOOP_THREAD is not None and _LOOP_THREAD.is_alive() and not _LOOP_STOP.is_set()
    if not scan_running:
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", "tools/batch_scan.py"],
                text=True,
                timeout=2,
            ).strip()
            scan_running = bool(out)
        except Exception:  # noqa: BLE001
            scan_running = False

    data = {
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
        "loop_running": loop_running,
        "loop": load_loop_status(),
        "config": load_config(),
    }
    _SYSTEM_CACHE["data"] = data
    _SYSTEM_CACHE["built_at"] = now
    return data


def _write_download_status(payload: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_STATUS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_loop_status(payload: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    LOOP_STATUS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_loop_status() -> dict:
    default = {
        "ok": True,
        "enabled": False,
        "state": "idle",
        "cycle": 0,
        "phase": "idle",
        "message": "Loop idle",
        "apps": 100,
        "threads": 12,
        "download_workers": 10,
    }
    if LOOP_STATUS_PATH.is_file():
        try:
            data = json.loads(LOOP_STATUS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                default.update(data)
        except json.JSONDecodeError:
            pass
    with _STATE_LOCK:
        alive = _LOOP_THREAD is not None and _LOOP_THREAD.is_alive() and not _LOOP_STOP.is_set()
    default["enabled"] = bool(alive or load_config().get("loop_enabled"))
    if alive:
        default["running"] = True
    else:
        default["running"] = False
        if default.get("state") in ("running", "starting"):
            default["state"] = "idle"
            default["phase"] = "idle"
    return default


def _scan_process_alive() -> bool:
    with _STATE_LOCK:
        if _SCAN_PROC is not None and _SCAN_PROC.poll() is None:
            return True
    try:
        out = subprocess.check_output(["pgrep", "-f", "tools/batch_scan.py"], text=True).strip()
        return bool(out)
    except Exception:  # noqa: BLE001
        return False


def _download_process_alive() -> bool:
    with _STATE_LOCK:
        return _DOWNLOAD_PROC is not None and _DOWNLOAD_PROC.poll() is None


def stop_download() -> dict:
    global _DOWNLOAD_PROC
    with _STATE_LOCK:
        proc = _DOWNLOAD_PROC
        _DOWNLOAD_PROC = None
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), 15)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except OSError:
                pass
    try:
        subprocess.run(["pkill", "-f", "tools/fdroid_download.py"], check=False, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    _write_download_status({
        "ok": True,
        "state": "stopped",
        "finished_at": _utc_now(),
        "message": "Download stopped",
    })
    _SYSTEM_CACHE["built_at"] = 0.0
    return {"ok": True, "message": "Download stopped"}


def stop_scan() -> dict:
    global _SCAN_PROC
    with _STATE_LOCK:
        proc = _SCAN_PROC
        _SCAN_PROC = None
    # Prefer tracked proc, but also kill orphan batch_scan children.
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), 15)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except OSError:
                pass
    try:
        subprocess.run(["pkill", "-f", "tools/batch_scan.py"], check=False, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    _SYSTEM_CACHE["built_at"] = 0.0
    return {"ok": True, "message": "Scan stopped"}


def _wait_until(predicate, timeout: float | None = None, poll: float = 2.0) -> bool:
    """Wait until predicate() is True or stop/timeout. Returns True if predicate met."""
    deadline = None if timeout is None else (time.time() + timeout)
    while not _LOOP_STOP.is_set():
        if predicate():
            return True
        if deadline is not None and time.time() >= deadline:
            return predicate()
        _LOOP_STOP.wait(poll)
    return predicate()


def start_download(count: int, workers: int | None = None) -> dict:
    global _DOWNLOAD_PROC
    workers_n = max(1, min(32, int(workers if workers is not None else load_config().get("download_workers") or 10)))
    cfg = save_config({"download_count": count, "download_workers": workers_n})
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
            "workers": workers_n,
            "started_at": _utc_now(),
        })
        venv_python = ROOT / ".venv" / "bin" / "python3"
        python = str(venv_python) if venv_python.is_file() else sys.executable
        cmd = [
            python,
            str(TOOLS / "fdroid_download.py"),
            "-n",
            str(count),
            "-j",
            str(workers_n),
            "-o",
            str(APKS_DIR),
            "--results",
            str(RESULTS_DIR),
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
            "workers": workers_n,
            "exit_code": code,
            "finished_at": _utc_now(),
            "apk_count": len(list(APKS_DIR.glob("*.apk"))) if APKS_DIR.is_dir() else 0,
        })

    threading.Thread(target=_watch, daemon=True).start()
    return {
        "ok": True,
        "state": "started",
        "requested": count,
        "workers": workers_n,
        "pid": proc.pid,
        "config": cfg,
        "message": (
            f"Downloading {count} new APKs with {workers_n} parallel workers "
            "(skipping packages already on disk or scanned)"
        ),
    }


def _loop_worker() -> None:
    cycle = int(load_loop_status().get("cycle") or 0)
    while not _LOOP_STOP.is_set():
        cfg = load_config()
        if not cfg.get("loop_enabled"):
            break
        apps = int(cfg.get("loop_apps") or 100)
        threads_n = int(cfg.get("loop_threads") or cfg.get("threads") or 12)
        workers_n = int(cfg.get("loop_download_workers") or cfg.get("download_workers") or 10)
        cycle += 1
        _write_loop_status({
            "ok": True,
            "enabled": True,
            "running": True,
            "state": "running",
            "phase": "downloading",
            "cycle": cycle,
            "apps": apps,
            "threads": threads_n,
            "download_workers": workers_n,
            "message": f"Cycle {cycle}: downloading {apps} APKs ({workers_n} workers)",
            "updated_at": _utc_now(),
        })

        # Wait if a manual download is still finishing.
        _wait_until(lambda: not _download_process_alive(), poll=2.0)
        if _LOOP_STOP.is_set():
            break
        dl = start_download(apps, workers=workers_n)
        if not dl.get("ok") and dl.get("error_code") != "BUSY":
            _write_loop_status({
                "ok": False,
                "enabled": True,
                "running": True,
                "state": "running",
                "phase": "download_error",
                "cycle": cycle,
                "apps": apps,
                "threads": threads_n,
                "download_workers": workers_n,
                "message": f"Cycle {cycle}: download failed — {dl.get('error')}",
                "updated_at": _utc_now(),
            })
            _LOOP_STOP.wait(10.0)
            continue
        _wait_until(lambda: not _download_process_alive(), poll=2.0)
        if _LOOP_STOP.is_set():
            break

        selected = 0
        downloaded = 0
        manifest = APKS_DIR / "fdroid-manifest.json"
        if manifest.is_file():
            try:
                man = json.loads(manifest.read_text(encoding="utf-8"))
                selected = int(man.get("selected") or 0)
                downloaded = int(man.get("downloaded") or 0)
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass

        _write_loop_status({
            "ok": True,
            "enabled": True,
            "running": True,
            "state": "running",
            "phase": "scanning",
            "cycle": cycle,
            "apps": apps,
            "threads": threads_n,
            "download_workers": workers_n,
            "message": (
                f"Cycle {cycle}: scanning with {threads_n} threads "
                f"(downloaded {downloaded}/{selected})"
            ),
            "updated_at": _utc_now(),
        })
        scan = start_scan(threads_n)
        if not scan.get("ok"):
            _write_loop_status({
                "ok": False,
                "enabled": True,
                "running": True,
                "state": "running",
                "phase": "scan_error",
                "cycle": cycle,
                "apps": apps,
                "threads": threads_n,
                "download_workers": workers_n,
                "message": f"Cycle {cycle}: scan failed — {scan.get('error')}",
                "updated_at": _utc_now(),
            })
            _LOOP_STOP.wait(10.0)
            continue

        # Give the scanner a moment to flip status.json to running.
        time.sleep(2.0)
        _wait_until(lambda: not _scan_process_alive(), poll=3.0)
        if _LOOP_STOP.is_set():
            break

        backoff = 30.0 if selected == 0 else 3.0
        _write_loop_status({
            "ok": True,
            "enabled": True,
            "running": True,
            "state": "running",
            "phase": "cycle_done",
            "cycle": cycle,
            "apps": apps,
            "threads": threads_n,
            "download_workers": workers_n,
            "message": (
                f"Cycle {cycle} complete"
                + (" — no new apps, waiting before retry" if selected == 0 else " — starting next")
            ),
            "updated_at": _utc_now(),
        })
        # Brief pause between cycles so the UI can show cycle_done.
        _LOOP_STOP.wait(backoff)

    save_config({"loop_enabled": False})
    _write_loop_status({
        "ok": True,
        "enabled": False,
        "running": False,
        "state": "stopped",
        "phase": "idle",
        "cycle": cycle,
        "message": "Loop stopped",
        "updated_at": _utc_now(),
    })


def start_loop(
    apps: int | None = None,
    threads: int | None = None,
    download_workers: int | None = None,
) -> dict:
    global _LOOP_THREAD
    patch: dict = {"loop_enabled": True}
    if apps is not None:
        patch["loop_apps"] = apps
        patch["download_count"] = apps
    if threads is not None:
        patch["loop_threads"] = threads
        patch["threads"] = threads
    if download_workers is not None:
        patch["loop_download_workers"] = download_workers
        patch["download_workers"] = download_workers
    cfg = save_config(patch)

    # Read cycle outside the lock — never call load_loop_status while holding
    # _STATE_LOCK with a non-reentrant lock (that deadlocked the whole API).
    prev_cycle = int(load_loop_status().get("cycle") or 0)

    with _STATE_LOCK:
        already = _LOOP_THREAD is not None and _LOOP_THREAD.is_alive() and not _LOOP_STOP.is_set()
        if already:
            started = False
        else:
            _LOOP_STOP.clear()
            _LOOP_THREAD = threading.Thread(target=_loop_worker, name="auto-loop", daemon=True)
            _LOOP_THREAD.start()
            started = True

    if not started:
        return {
            "ok": True,
            "state": "already_running",
            "config": cfg,
            "loop": load_loop_status(),
            "message": "Loop already running — settings updated for next cycle",
        }

    _write_loop_status({
        "ok": True,
        "enabled": True,
        "running": True,
        "state": "starting",
        "phase": "starting",
        "cycle": prev_cycle,
        "apps": cfg["loop_apps"],
        "threads": cfg["loop_threads"],
        "download_workers": cfg["loop_download_workers"],
        "message": "Starting auto loop",
        "updated_at": _utc_now(),
    })
    _SYSTEM_CACHE["built_at"] = 0.0
    return {
        "ok": True,
        "state": "started",
        "config": cfg,
        "loop": load_loop_status(),
        "message": (
            f"Auto loop started: {cfg['loop_apps']} apps/cycle, "
            f"{cfg['loop_threads']} scan threads, "
            f"{cfg['loop_download_workers']} download workers"
        ),
    }


def stop_loop() -> dict:
    save_config({"loop_enabled": False})
    _LOOP_STOP.set()
    # Stop immediately — kill in-flight download + scan started by the loop.
    dl = stop_download()
    sc = stop_scan()
    _write_loop_status({
        "ok": True,
        "enabled": False,
        "running": False,
        "state": "stopped",
        "phase": "idle",
        "cycle": int(load_loop_status().get("cycle") or 0),
        "message": "Loop stopped (download and scan halted)",
        "updated_at": _utc_now(),
    })
    _SYSTEM_CACHE["built_at"] = 0.0
    return {
        "ok": True,
        "state": "stopped",
        "download": dl,
        "scan": sc,
        "loop": load_loop_status(),
        "message": "Loop stopped — download and scan halted",
    }


def clear_downloaded_apks() -> dict:
    """Delete all .apk files from the APKs directory (keeps scan results)."""
    with _STATE_LOCK:
        download_busy = _DOWNLOAD_PROC is not None and _DOWNLOAD_PROC.poll() is None
        scan_busy = _SCAN_PROC is not None and _SCAN_PROC.poll() is None
    if download_busy:
        return {"ok": False, "error": "Download is running — stop it first", "error_code": "BUSY"}
    if scan_busy:
        return {"ok": False, "error": "Scan is running — stop it before deleting APKs", "error_code": "BUSY"}

    APKS_DIR.mkdir(parents=True, exist_ok=True)
    removed = 0
    failed = 0
    errors: list[str] = []
    for path in sorted(APKS_DIR.glob("*.apk")):
        if not path.is_file():
            continue
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            failed += 1
            if len(errors) < 5:
                errors.append(f"{path.name}: {exc}")
    # Also drop partial downloads
    for path in APKS_DIR.glob("*.apk.part"):
        try:
            path.unlink()
        except OSError:
            pass
    remaining = len(list(APKS_DIR.glob("*.apk")))
    _SYSTEM_CACHE["built_at"] = 0.0
    return {
        "ok": failed == 0,
        "removed": removed,
        "failed": failed,
        "remaining": remaining,
        "errors": errors,
        "message": f"Removed {removed} downloaded APK(s)" + (f"; {failed} failed" if failed else ""),
    }


def start_scan(threads: int | None = None) -> dict:
    global _SCAN_PROC
    cfg = save_config({"threads": threads} if threads is not None else {})
    threads_n = int(cfg["threads"])
    old_proc: subprocess.Popen | None = None
    with _STATE_LOCK:
        if _SCAN_PROC is not None and _SCAN_PROC.poll() is None:
            old_proc = _SCAN_PROC
            _SCAN_PROC = None

    # Kill/wait outside the lock so /api/status never blocks on scan restart.
    if old_proc is not None:
        try:
            os.killpg(os.getpgid(old_proc.pid), 15)
        except OSError:
            try:
                old_proc.terminate()
            except OSError:
                pass
        try:
            old_proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                old_proc.kill()
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
        "-a",
        "-j 2",
        "--status",
        str(RESULTS_DIR / "status.json"),
    ]
    log_fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
    with _STATE_LOCK:
        _SCAN_PROC = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        proc = _SCAN_PROC
    _SYSTEM_CACHE["built_at"] = 0.0
    return {
        "ok": True,
        "state": "started",
        "threads": threads_n,
        "pid": proc.pid,
        "config": cfg,
        "message": f"Batch scan started with {threads_n} threads",
    }


def _iter_result_jobs(status_jobs: list | None = None) -> list[dict]:
    """Merge status jobs with on-disk per-APK JSON (prefer full findings).

    Returns jobs newest-first so Other APIs list newest discoveries first.
    """
    jobs: list[tuple[float, dict]] = []
    for idx, job in enumerate(status_jobs or []):
        if isinstance(job, dict) and job.get("apk"):
            # Status jobs are appended oldest→newest; use index as fallback time.
            jobs.append((float(idx), dict(job)))
    if RESULTS_DIR.is_dir():
        for path in RESULTS_DIR.glob("*.json"):
            if path.name in _META_SKIP:
                continue
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(job, dict) and job.get("apk"):
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    mtime = 0.0
                job = dict(job)
                job["_mtime"] = mtime
                jobs.append((mtime, job))
    by_name: dict[str, tuple[float, dict]] = {}
    for mtime, job in jobs:
        name = job.get("apk") or ""
        if not name:
            continue
        prev = by_name.get(name)
        if prev is None:
            by_name[name] = (mtime, job)
            continue
        prev_mtime, prev_job = prev
        prev_has = bool(prev_job.get("findings") or prev_job.get("results"))
        cur_has = bool(job.get("findings") or job.get("results"))
        prev_pri = len(prev_job.get("priority_lines") or []) + len(prev_job.get("other_lines") or [])
        cur_pri = len(job.get("priority_lines") or []) + len(job.get("other_lines") or [])
        if cur_has and not prev_has:
            by_name[name] = (mtime, job)
        elif cur_has == prev_has and cur_pri > prev_pri:
            by_name[name] = (mtime, job)
        elif cur_has == prev_has and cur_pri == prev_pri and mtime >= prev_mtime:
            by_name[name] = (mtime, job)
    ordered = sorted(by_name.values(), key=lambda item: item[0], reverse=True)
    return [job for _, job in ordered]


def _results_cache_key() -> tuple:
    """Cheap fingerprint of results dir + status so we can skip full re-aggregates."""
    status_mtime = 0.0
    status_path = RESULTS_DIR / "status.json"
    if status_path.is_file():
        try:
            status_mtime = status_path.stat().st_mtime
        except OSError:
            status_mtime = 0.0
    newest = status_mtime
    count = 0
    if RESULTS_DIR.is_dir():
        for path in RESULTS_DIR.glob("*.json"):
            if path.name in _META_SKIP:
                continue
            count += 1
            try:
                newest = max(newest, path.stat().st_mtime)
            except OSError:
                pass
    return (count, round(newest, 3), round(status_mtime, 3))


def _cached_aggregate(status_jobs: list | None = None, force: bool = False) -> dict:
    """Aggregate results with a short-lived cache — /api/results was taking 15–25s."""
    key = _results_cache_key()
    now = time.time()
    cached = _RESULTS_CACHE.get("agg")
    if (
        not force
        and cached is not None
        and _RESULTS_CACHE.get("key") == key
        and (now - float(_RESULTS_CACHE.get("built_at") or 0)) < 15.0
    ):
        return cached
    jobs = _iter_result_jobs(status_jobs or [])
    agg = aggregate_results(jobs)
    _RESULTS_CACHE["key"] = key
    _RESULTS_CACHE["agg"] = agg
    _RESULTS_CACHE["built_at"] = now
    return agg


def _warm_results_cache() -> None:
    try:
        collect_results(RESULTS_DIR / "status.json")
    except Exception:  # noqa: BLE001
        pass


def load_status(status_path: Path) -> dict:
    if status_path.is_file():
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Detect dead scanners: status says running but process is gone.
                with _STATE_LOCK:
                    alive = _SCAN_PROC is not None and _SCAN_PROC.poll() is None
                if data.get("state") == "running" and not alive:
                    try:
                        out = subprocess.check_output(
                            ["pgrep", "-f", "tools/batch_scan.py"],
                            text=True,
                            timeout=2,
                        ).strip()
                        alive = bool(out)
                    except Exception:  # noqa: BLE001
                        alive = False
                if data.get("state") == "running" and not alive:
                    data["state"] = "idle"
                    data["active"] = {}
                    data["current"] = []
                    data["scan_dead"] = True

                # Keep /api/status fast: do NOT re-read every per-APK JSON here.
                # Full merge happens in collect_results() with a cache.
                data.setdefault("priority_lines", [])
                data.setdefault("other_lines", [])
                data.setdefault("raw_lines", list(data.get("priority_lines") or []) + list(data.get("other_lines") or []))
                data.setdefault("aws_pairs", [])
                data["counts"] = data.get("counts") or {}
                data["demo"] = False
                return data
        except json.JSONDecodeError:
            return {"ok": False, "error": "Invalid status JSON", "demo": False}
    demo = dict(DEMO_STATUS)
    return demo


def collect_results(status_path: Path, persist: bool = True) -> dict:
    status = load_status(status_path)
    agg = _cached_aggregate(status.get("jobs") or [], force=False)
    agg = dict(agg)
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
    if not persist:
        return agg
    # Refresh status-facing lines from the authoritative merge (best-effort).
    try:
        if status_path.is_file():
            data = json.loads(status_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["priority_lines"] = agg.get("priority_lines") or []
                data["other_lines"] = agg.get("other_lines") or []
                data["raw_lines"] = agg.get("lines") or []
                data["aws_pairs"] = agg.get("aws_pairs") or []
                tmp = status_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                tmp.replace(status_path)
    except Exception:  # noqa: BLE001
        pass
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
            sys = system_stats()
            data["system"] = sys
            data["config"] = sys.get("config") or load_config()
            data["loop"] = sys.get("loop") or load_loop_status()
            self._json(data)
            return

        if path == "/api/health":
            self._json({"ok": True, "status_path": str(self.status_path)})
            return

        if path == "/api/system":
            self._json(system_stats())
            return

        if path in ("/api/loop", "/api/loop/status"):
            self._json({"ok": True, "loop": load_loop_status(), "config": load_config()})
            return

        if path == "/api/config":
            self._json({"ok": True, "config": load_config()})
            return

        if path in ("/api/results", "/api/results.json"):
            # Avoid rewriting status.json on every poll — cache handles speed.
            self._json(collect_results(self.status_path, persist=False))
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
                    "/api/apks/clear",
                    "/api/threads",
                    "/api/loop",
                    "/api/loop/stop",
                    "/apkleaks-skills/dashboard",
                ],
            },
            404,
        )

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        body = self._read_json_body()

        if path in ("/api/download", "/api/download/start"):
            cfg = load_config()
            count = body.get("count", cfg.get("download_count", 100))
            workers = body.get("workers", body.get("download_workers", cfg.get("download_workers", 10)))
            try:
                count = int(count)
                workers = int(workers)
            except (TypeError, ValueError):
                self._json({"ok": False, "error": "count/workers must be integers"}, 400)
                return
            if count < 1:
                self._json({"ok": False, "error": "count must be >= 1"}, 400)
                return
            if workers < 1 or workers > 32:
                self._json({"ok": False, "error": "workers must be 1..32"}, 400)
                return
            self._json(start_download(count, workers=workers))
            return

        if path in ("/api/apks/clear", "/api/download/clear"):
            self._json(clear_downloaded_apks())
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

        if path in ("/api/loop", "/api/loop/start"):
            cfg = load_config()
            apps = body.get("apps", body.get("loop_apps", cfg.get("loop_apps", 100)))
            threads = body.get("threads", body.get("loop_threads", cfg.get("loop_threads", 12)))
            workers = body.get(
                "download_workers",
                body.get("loop_download_workers", cfg.get("loop_download_workers", 10)),
            )
            try:
                apps = int(apps)
                threads = int(threads)
                workers = int(workers)
            except (TypeError, ValueError):
                self._json({"ok": False, "error": "apps/threads/download_workers must be integers"}, 400)
                return
            if apps < 1 or apps > 5000:
                self._json({"ok": False, "error": "apps must be 1..5000"}, 400)
                return
            if threads < 1 or threads > 32:
                self._json({"ok": False, "error": "threads must be 1..32"}, 400)
                return
            if workers < 1 or workers > 32:
                self._json({"ok": False, "error": "download_workers must be 1..32"}, 400)
                return
            self._json(start_loop(apps=apps, threads=threads, download_workers=workers))
            return

        if path in ("/api/loop/stop",):
            self._json(stop_loop())
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
    # Warm results cache in the background so first UI poll stays snappy.
    threading.Thread(target=_warm_results_cache, name="warm-results-cache", daemon=True).start()
    # Resume auto-loop if it was left enabled across a dashboard restart.
    if load_config().get("loop_enabled"):
        start_loop()
    server = ThreadingHTTPServer((args.host, args.port), StatusHandler)
    print(f"Dashboard API listening on http://{args.host}:{args.port}")
    print(f"Status file: {StatusHandler.status_path}")
    print("GET /api/status /api/system /api/results /api/results.txt /api/loop")
    print("POST /api/download  /api/apks/clear  /api/threads  /api/loop  /api/loop/stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        stop_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
