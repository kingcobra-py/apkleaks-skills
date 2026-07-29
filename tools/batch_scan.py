#!/usr/bin/env python3
"""Threaded multi-APK scanner with progress bar, logs, and live status JSON."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


LOG = logging.getLogger("batch_scan")
_STATUS_LOCK = threading.Lock()
_CLI = None
_CLI_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_cli():
    global _CLI
    with _CLI_LOCK:
        if _CLI is not None:
            return _CLI
        cli_path = ROOT / "apkleaks-ai-cli.py"
        spec = importlib.util.spec_from_file_location("apkleaks_ai_cli", cli_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load CLI from {cli_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CLI = module
        return _CLI


def _empty_status(total: int, threads: int, input_dir: str, output_dir: str) -> dict[str, Any]:
    return {
        "ok": True,
        "state": "running",
        "started_at": _utc_now(),
        "updated_at": _utc_now(),
        "finished_at": None,
        "input_dir": input_dir,
        "output_dir": output_dir,
        "threads": threads,
        "progress": {
            "total": total,
            "completed": 0,
            "succeeded": 0,
            "failed": 0,
            "percent": 0.0,
        },
        "counts": {
            "findings": 0,
            "critical": 0,
            "high": 0,
            "has_aws": 0,
            "has_sendgrid": 0,
            "has_stripe": 0,
        },
        "current": [],
        "jobs": [],
        "logs": [],
    }


def _write_status(path: Path, status: dict[str, Any]) -> None:
    status["updated_at"] = _utc_now()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
    tmp.replace(path)


def _append_log(status: dict[str, Any], level: str, message: str, limit: int = 200) -> None:
    status["logs"].append({"ts": _utc_now(), "level": level, "message": message})
    if len(status["logs"]) > limit:
        status["logs"] = status["logs"][-limit:]


def _interesting_hits(findings: list[dict[str, Any]]) -> dict[str, bool]:
    names = {f.get("name", "") for f in findings}
    return {
        "aws": any(
            n in names
            for n in ("AWS_API_Key", "Amazon_AWS_Access_Key_ID", "AWS_Secret_Access_Key")
        ),
        "sendgrid": "SendGrid_API_Key" in names,
        "stripe": any(n.startswith("Stripe_") for n in names),
    }


def _scan_one(apk: Path, severity: str | None, pattern: str | None, jadx_args: str | None) -> dict[str, Any]:
    cli = _load_cli()
    args = argparse.Namespace(
        file=str(apk),
        pattern=pattern,
        jadx_args=jadx_args,
        severity=severity,
        output=None,
    )
    started = time.time()
    result = cli.cmd_scan(args)
    duration_ms = int((time.time() - started) * 1000)
    data = (result or {}).get("data") or {}
    findings = data.get("findings") or []
    hits = _interesting_hits(findings)
    return {
        "apk": apk.name,
        "path": str(apk),
        "ok": bool((result or {}).get("ok")),
        "error": (result or {}).get("error"),
        "error_code": (result or {}).get("error_code"),
        "duration_ms": duration_ms,
        "has_critical": bool(data.get("has_critical")),
        "finding_count": len(findings),
        "findings": findings,
        "hits": hits,
    }


def discover_apks(input_path: Path) -> list[Path]:
    if input_path.is_file() and input_path.suffix.lower() == ".apk":
        return [input_path]
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input path not found: {input_path}")
    return sorted(p for p in input_path.rglob("*.apk") if p.is_file())


def run_batch(
    input_dir: Path,
    output_dir: Path,
    threads: int = 4,
    severity: str | None = "high",
    pattern: str | None = None,
    jadx_args: str | None = None,
    status_path: Path | None = None,
) -> dict[str, Any]:
    apks = discover_apks(input_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    status_file = status_path or (output_dir / "status.json")
    status = _empty_status(len(apks), threads, str(input_dir), str(output_dir))
    _append_log(status, "info", f"Discovered {len(apks)} APK(s); threads={threads}")
    _write_status(status_file, status)

    if not apks:
        status["state"] = "completed"
        status["finished_at"] = _utc_now()
        _append_log(status, "warning", "No APK files found")
        _write_status(status_file, status)
        return status

    progress = tqdm(total=len(apks), desc="Scanning APKs", unit="apk") if tqdm else None

    def mark_start(name: str) -> None:
        with _STATUS_LOCK:
            status["current"].append(name)
            _append_log(status, "info", f"Scanning {name}")
            _write_status(status_file, status)

    def mark_done(job: dict[str, Any]) -> None:
        with _STATUS_LOCK:
            if job["apk"] in status["current"]:
                status["current"].remove(job["apk"])
            status["jobs"].append(job)
            status["progress"]["completed"] += 1
            if job["ok"]:
                status["progress"]["succeeded"] += 1
            else:
                status["progress"]["failed"] += 1
            status["progress"]["percent"] = round(
                100.0 * status["progress"]["completed"] / max(1, status["progress"]["total"]), 1
            )
            status["counts"]["findings"] += job.get("finding_count", 0)
            for finding in job.get("findings") or []:
                sev = finding.get("severity")
                if sev in ("critical", "high"):
                    status["counts"][sev] = status["counts"].get(sev, 0) + 1
            hits = job.get("hits") or {}
            if hits.get("aws"):
                status["counts"]["has_aws"] += 1
            if hits.get("sendgrid"):
                status["counts"]["has_sendgrid"] += 1
            if hits.get("stripe"):
                status["counts"]["has_stripe"] += 1
            level = "info" if job["ok"] else "error"
            msg = (
                f"Done {job['apk']}: findings={job.get('finding_count', 0)} "
                f"ok={job['ok']} ({job.get('duration_ms', 0)} ms)"
            )
            _append_log(status, level, msg)
            LOG.log(logging.INFO if job["ok"] else logging.ERROR, msg)
            _write_status(status_file, status)

    def _worker(apk: Path) -> dict[str, Any]:
        mark_start(apk.name)
        try:
            return _scan_one(apk, severity, pattern, jadx_args)
        except Exception as exc:  # noqa: BLE001
            return {
                "apk": apk.name,
                "path": str(apk),
                "ok": False,
                "error": str(exc),
                "error_code": "SCAN_FAILED",
                "duration_ms": 0,
                "has_critical": False,
                "finding_count": 0,
                "findings": [],
                "hits": {"aws": False, "sendgrid": False, "stripe": False},
            }

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_worker, apk): apk for apk in apks}
        for fut in as_completed(futures):
            apk = futures[fut]
            job = fut.result()
            (output_dir / f"{apk.stem}.json").write_text(json.dumps(job, indent=2), encoding="utf-8")
            mark_done(job)
            if progress is not None:
                progress.update(1)
                progress.set_postfix(
                    ok=status["progress"]["succeeded"],
                    fail=status["progress"]["failed"],
                    findings=status["counts"]["findings"],
                )

    if progress is not None:
        progress.close()

    status["state"] = "completed"
    status["finished_at"] = _utc_now()
    _append_log(status, "info", "Batch scan completed")
    _write_status(status_file, status)
    (output_dir / "summary.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan multiple APKs in parallel with progress + status JSON",
    )
    parser.add_argument("-d", "--dir", required=True, help="Directory of APK files (or a single .apk)")
    parser.add_argument("-o", "--output", default="results", help="Output directory (default: results)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Worker threads (default: 4)")
    parser.add_argument(
        "-s",
        "--severity",
        default="high",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity filter (default: high)",
    )
    parser.add_argument("-p", "--pattern", default=None, help="Custom patterns JSON")
    parser.add_argument("-a", "--args", dest="jadx_args", default=None, help="Extra jadx args")
    parser.add_argument("--status", default=None, help="Status JSON path (default: <output>/status.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        status = run_batch(
            input_dir=Path(args.dir),
            output_dir=Path(args.output),
            threads=max(1, min(16, args.threads)),
            severity=args.severity,
            pattern=args.pattern,
            jadx_args=args.jadx_args,
            status_path=Path(args.status) if args.status else None,
        )
    except FileNotFoundError as exc:
        LOG.error("%s", exc)
        return 2

    print(json.dumps({
        "ok": True,
        "state": status["state"],
        "progress": status["progress"],
        "counts": status["counts"],
        "output_dir": status["output_dir"],
    }, indent=2))
    return 0 if status["progress"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
