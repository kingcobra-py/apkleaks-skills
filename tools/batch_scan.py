#!/usr/bin/env python3
"""Threaded multi-APK scanner with progress bar, logs, and live status JSON."""

from __future__ import annotations

import argparse
import builtins
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None

from results_format import aggregate_results, normalize_job_findings  # noqa: E402


LOG = logging.getLogger("batch_scan")
_STATUS_LOCK = threading.Lock()
_CLI = None
_CLI_LOCK = threading.Lock()
_INPUT_LOCK = threading.Lock()
_LOGS_SILENCED = False

PHASE_PERCENT = {
    "queued": 0,
    "starting": 8,
    "integrity": 18,
    "decompiling": 45,
    "scanning": 50,  # floor; live file progress maps 50→90
    "classifying": 92,
    "done": 100,
    "failed": 100,
}

# Scanning sub-progress range (percent) while matching patterns.
SCAN_PCT_START = 50
SCAN_PCT_END = 90

# Skip LinkFinder MIME-ish false positives (mirrors apkleaks.APKLeaks.extract).
_LINKFINDER_SKIP = re.compile(
    r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+"
)


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
        "active": {},  # apk -> live phase info
        "jobs": [],
        "logs": [],
        "raw_lines": [],
        "priority_lines": [],
        "other_lines": [],
        "aws_pairs": [],
    }


def _write_status(path: Path, status: dict[str, Any]) -> None:
    status["updated_at"] = _utc_now()
    # Refresh elapsed_ms for active apps
    now = time.time()
    for info in (status.get("active") or {}).values():
        started = info.get("_started_ts")
        if isinstance(started, (int, float)):
            info["elapsed_ms"] = int((now - started) * 1000)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    # Don't persist internal timestamps helper fields? Keep them — useful and small.
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


def _slim_job(job: dict[str, Any]) -> dict[str, Any]:
    """Keep status.json small — full findings stay in per-APK JSON files."""
    return {
        "apk": job.get("apk"),
        "path": job.get("path"),
        "ok": job.get("ok"),
        "error": job.get("error"),
        "error_code": job.get("error_code"),
        "duration_ms": job.get("duration_ms"),
        "has_critical": job.get("has_critical"),
        "finding_count": job.get("finding_count"),
        "priority_lines": job.get("priority_lines") or [],
        "other_lines": job.get("other_lines") or [],
        "aws_pairs": job.get("aws_pairs") or [],
        "hits": job.get("hits") or {},
        "phase": job.get("phase") or ("done" if job.get("ok") else "failed"),
    }


def _compile_pattern_rules(pattern_path: str | Path) -> list[tuple[str, re.Pattern[str]]]:
    """Load regex JSON into (name, compiled) pairs. List values expand to multiple rules."""
    with open(pattern_path, encoding="utf-8") as handle:
        regex = json.load(handle)
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for name, pattern in regex.items():
        patterns = pattern if isinstance(pattern, list) else [pattern]
        for p in patterns:
            if not isinstance(p, str) or not p:
                continue
            try:
                compiled.append((name, re.compile(p)))
            except re.error:
                LOG.warning("Skipping invalid regex for %s", name)
    return compiled


def _filter_linkfinder_secret(secret: str) -> str | None:
    if _LINKFINDER_SKIP.match(secret) is not None:
        return None
    if len(secret) >= 2 and secret.startswith("'") and secret.endswith("'"):
        return secret[1:-1]
    return secret


def _scan_percent(done: int, total: int) -> int:
    if total <= 0:
        return SCAN_PCT_END
    ratio = min(1.0, max(0.0, done / total))
    return int(SCAN_PCT_START + (SCAN_PCT_END - SCAN_PCT_START) * ratio)


def fast_scan_tempdir(
    tempdir: str | Path,
    pattern_path: str | Path,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict[str, Any]]:
    """Single-pass secret scan: walk each file once, apply all patterns.

    Upstream APKLeaks.scanning() walks the whole tree once per regex (~95 full
    passes), which looks frozen at a fixed UI percent for many minutes.
    """
    rules = _compile_pattern_rules(pattern_path)
    files: list[str] = []
    for fp, _, fnames in os.walk(tempdir):
        for fn in fnames:
            files.append(os.path.join(fp, fn))

    found: dict[str, set[str]] = {}
    total = len(files)
    last_report = 0
    report_every = max(1, total // 40) if total else 1

    if on_progress:
        on_progress(0, total)

    for idx, filepath in enumerate(files, 1):
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    for name, matcher in rules:
                        mo = matcher.search(line)
                        if not mo:
                            continue
                        secret = mo.group()
                        if name == "LinkFinder":
                            secret = _filter_linkfinder_secret(secret)
                            if secret is None:
                                continue
                        found.setdefault(name, set()).add(secret)
        except OSError:
            pass

        if on_progress and (idx == total or idx - last_report >= report_every):
            last_report = idx
            on_progress(idx, total)

    results: list[dict[str, Any]] = []
    for name, matches in found.items():
        if matches:
            results.append({"name": name, "matches": sorted(matches)})
    return results


def _fast_scanning(
    runner: Any,
    on_progress: Callable[[int, int], None] | None = None,
) -> None:
    """Replace runner.scanning() with single-pass walk + live progress."""
    package = ""
    apk_obj = getattr(runner, "apk", None)
    if apk_obj is not None:
        package = getattr(apk_obj, "package", "") or ""
    runner.out_json["package"] = package
    runner.out_json["results"] = []
    results = fast_scan_tempdir(runner.tempdir, runner.pattern, on_progress=on_progress)
    runner.out_json["results"] = results
    if results:
        runner.scanned = True


def _scan_one(
    apk: Path,
    severity: str | None,
    pattern: str | None,
    jadx_args: str | None,
    on_phase: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Scan one APK with optional phase callbacks: on_phase(phase, message, percent=None)."""
    cli = _load_cli()

    def phase(name: str, message: str, percent: int | None = None) -> None:
        if on_phase:
            on_phase(name, message, percent)

    phase("starting", "Preparing scanner")
    if not apk.is_file():
        return {
            "apk": apk.name,
            "path": str(apk),
            "ok": False,
            "error": f"APK file not found: {apk}",
            "error_code": "FILE_NOT_FOUND",
            "duration_ms": 0,
            "has_critical": False,
            "finding_count": 0,
            "findings": [],
            "raw_lines": [],
            "priority_lines": [],
            "other_lines": [],
            "aws_pairs": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False},
            "phase": "failed",
        }

    started = time.time()
    global _LOGS_SILENCED
    with _CLI_LOCK:
        if not _LOGS_SILENCED:
            cli._silence_logs()
            _LOGS_SILENCED = True

    class FakeArgs:
        pass

    fake = FakeArgs()
    fake.file = str(apk)
    fake.output = None
    fake.args = jadx_args
    fake.json = True
    fake.pattern = pattern

    merged_pattern_file = None
    runner = None
    try:
        if pattern is None and getattr(cli, "_RUNTIME_RULES", None):
            merged, err = cli._get_merged_patterns()
            if err:
                raise RuntimeError(f"Failed to merge patterns: {err}")
            if merged is not None and cli._RUNTIME_RULES:
                merged_pattern_file = tempfile.mktemp(suffix=".json", prefix="apkleaks-rules-")
                with open(merged_pattern_file, "w", encoding="utf-8") as fh:
                    json.dump(merged, fh, ensure_ascii=False)
                fake.pattern = merged_pattern_file

        phase("integrity", "Checking APK integrity / jadx")
        cli._ensure_imports()
        runner = cli._APKLeaks(fake)
        # Only serialize the interactive integrity prompt — do NOT redirect
        # sys.stdout/sys.stderr (that races across worker threads).
        with _INPUT_LOCK:
            original_input = builtins.input
            builtins.input = lambda _: "Y"
            try:
                runner.integrity()
            finally:
                builtins.input = original_input

        phase("decompiling", "Decompiling with jadx (this can take a while)")
        runner.decompile()

        def on_scan_progress(done: int, total: int) -> None:
            pct = _scan_percent(done, total)
            if total <= 0:
                phase("scanning", "No decompiled files to scan", pct)
            else:
                phase("scanning", f"Scanning files {done}/{total}", pct)

        phase("scanning", "Matching secret patterns (single pass)", SCAN_PCT_START)
        # Single-pass walk — upstream scanning() re-walks the tree per regex and
        # freezes the UI at a fixed percent for a very long time.
        _fast_scanning(runner, on_progress=on_scan_progress)

        phase("classifying", "Classifying findings", PHASE_PERCENT["classifying"])
        raw_results = runner.out_json.copy()
        results_list = raw_results.get("results", [])
        classified = cli._classify_findings(results_list)

        if severity:
            min_sev = cli.SEVERITY_ORDER.get(severity, 3)
            classified["results"] = [
                r for r in classified["results"]
                if cli.SEVERITY_ORDER.get(r["severity"], 3) <= min_sev
            ]
            classified["total_findings"] = sum(r["match_count"] for r in classified["results"])
            classified["severity_counts"] = {}
            for r in classified["results"]:
                classified["severity_counts"][r["severity"]] = (
                    classified["severity_counts"].get(r["severity"], 0) + r["match_count"]
                )
            classified["has_critical"] = classified["severity_counts"].get("critical", 0) > 0

        classified["package"] = raw_results.get("package", "")
        findings = classified.get("results") or []
        hits = _interesting_hits(findings)
        norm = normalize_job_findings({"findings": findings})
        duration_ms = int((time.time() - started) * 1000)
        error_code = "NO_FINDINGS" if classified.get("total_findings", 0) == 0 else None
        phase("done", f"Done — {norm['finding_count']} secret(s)")
        return {
            "apk": apk.name,
            "path": str(apk),
            "ok": True,
            "error": None,
            "error_code": error_code,
            "duration_ms": duration_ms,
            "has_critical": bool(classified.get("has_critical")),
            "finding_count": norm["finding_count"],
            "findings": findings,
            "raw_lines": norm["raw_lines"],
            "priority_lines": norm["priority_lines"],
            "other_lines": norm["other_lines"],
            "aws_pairs": norm["aws_pairs"],
            "hits": hits,
            "phase": "done",
            "package": classified.get("package") or "",
        }
    except SystemExit as exc:
        detail = f"Scan aborted (exit code {exc.code})"
        phase("failed", detail[:120])
        return {
            "apk": apk.name,
            "path": str(apk),
            "ok": False,
            "error": detail,
            "error_code": "SCAN_FAILED",
            "duration_ms": int((time.time() - started) * 1000),
            "has_critical": False,
            "finding_count": 0,
            "findings": [],
            "raw_lines": [],
            "priority_lines": [],
            "other_lines": [],
            "aws_pairs": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False},
            "phase": "failed",
        }
    except Exception as exc:  # noqa: BLE001
        detail = str(exc)
        phase("failed", detail[:120])
        return {
            "apk": apk.name,
            "path": str(apk),
            "ok": False,
            "error": detail,
            "error_code": "SCAN_FAILED",
            "duration_ms": int((time.time() - started) * 1000),
            "has_critical": False,
            "finding_count": 0,
            "findings": [],
            "raw_lines": [],
            "priority_lines": [],
            "other_lines": [],
            "aws_pairs": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False},
            "phase": "failed",
        }
    finally:
        if runner and hasattr(runner, "fileout"):
            try:
                runner.fileout.close()
            except Exception:  # noqa: BLE001
                pass
        if runner and hasattr(runner, "tempdir") and os.path.isdir(runner.tempdir):
            try:
                shutil.rmtree(runner.tempdir)
            except Exception:  # noqa: BLE001
                pass
        if merged_pattern_file and os.path.isfile(merged_pattern_file):
            try:
                os.remove(merged_pattern_file)
            except Exception:  # noqa: BLE001
                pass


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
    # Pre-populate queue snapshot so UI can show pending apps
    status["queue_preview"] = [p.name for p in apks[:50]]
    _append_log(status, "info", f"Discovered {len(apks)} APK(s); threads={threads}")
    _write_status(status_file, status)

    if not apks:
        status["state"] = "completed"
        status["finished_at"] = _utc_now()
        _append_log(status, "warning", "No APK files found")
        _write_status(status_file, status)
        return status

    progress = tqdm(total=len(apks), desc="Scanning APKs", unit="apk") if tqdm else None

    def set_phase(
        name: str,
        phase: str,
        message: str,
        percent: int | None = None,
    ) -> None:
        with _STATUS_LOCK:
            info = status["active"].get(name) or {}
            if "_started_ts" not in info:
                info["_started_ts"] = time.time()
                info["started_at"] = _utc_now()
            pct = int(percent) if percent is not None else PHASE_PERCENT.get(phase, 0)
            pct = max(0, min(100, pct))
            prev_phase = info.get("phase")
            prev_pct = info.get("percent")
            prev_msg = info.get("message")
            now = time.time()
            last_write = float(info.get("_last_write_ts") or 0.0)
            info.update(
                {
                    "apk": name,
                    "phase": phase,
                    "percent": pct,
                    "message": message,
                    "elapsed_ms": int((now - info["_started_ts"]) * 1000),
                }
            )
            status["active"][name] = info
            if name not in status["current"] and phase not in ("done", "failed"):
                status["current"].append(name)
            # Throttle disk writes during dense scanning progress updates.
            changed = (
                phase != prev_phase
                or message != prev_msg
                or prev_pct is None
                or abs(pct - int(prev_pct)) >= 2
                or phase in ("done", "failed", "classifying")
                or (now - last_write) >= 1.5
            )
            if changed:
                info["_last_write_ts"] = now
                _write_status(status_file, status)

    def mark_start(name: str) -> None:
        with _STATUS_LOCK:
            status["active"][name] = {
                "apk": name,
                "phase": "starting",
                "percent": PHASE_PERCENT["starting"],
                "message": "Starting worker",
                "started_at": _utc_now(),
                "_started_ts": time.time(),
                "elapsed_ms": 0,
            }
            if name not in status["current"]:
                status["current"].append(name)
            _append_log(status, "info", f"Scanning {name}")
            _write_status(status_file, status)

    def mark_done(job: dict[str, Any]) -> None:
        with _STATUS_LOCK:
            name = job["apk"]
            if name in status["current"]:
                status["current"].remove(name)
            # Keep finished active entry briefly with final phase, then drop
            status["active"].pop(name, None)
            slim = _slim_job(job)
            status["jobs"].append(slim)
            # Cap jobs retained in status.json for UI speed
            if len(status["jobs"]) > 300:
                status["jobs"] = status["jobs"][-300:]
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
            if hits.get("aws") or job.get("aws_pairs"):
                status["counts"]["has_aws"] += 1
            if hits.get("sendgrid"):
                status["counts"]["has_sendgrid"] += 1
            if hits.get("stripe"):
                status["counts"]["has_stripe"] += 1
            for line in job.get("priority_lines") or []:
                if line not in status["priority_lines"]:
                    status["priority_lines"].append(line)
            for line in job.get("other_lines") or []:
                if line not in status["other_lines"] and line not in status["priority_lines"]:
                    status["other_lines"].append(line)
            status["raw_lines"] = list(status["priority_lines"]) + list(status["other_lines"])
            for pair in job.get("aws_pairs") or []:
                if pair not in status["aws_pairs"]:
                    status["aws_pairs"].append(pair)
            out_dir = status_file.parent
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "results.txt").write_text(
                "\n".join(status["raw_lines"]) + ("\n" if status["raw_lines"] else ""),
                encoding="utf-8",
            )
            (out_dir / "priority-results.txt").write_text(
                "\n".join(status["priority_lines"]) + ("\n" if status["priority_lines"] else ""),
                encoding="utf-8",
            )
            (out_dir / "other-results.txt").write_text(
                "\n".join(status["other_lines"]) + ("\n" if status["other_lines"] else ""),
                encoding="utf-8",
            )
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

        def on_phase(phase: str, message: str, percent: int | None = None) -> None:
            set_phase(apk.name, phase, message, percent)

        try:
            return _scan_one(apk, severity, pattern, jadx_args, on_phase=on_phase)
        except Exception as exc:  # noqa: BLE001
            set_phase(apk.name, "failed", str(exc)[:120])
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
                "raw_lines": [],
                "priority_lines": [],
                "other_lines": [],
                "aws_pairs": [],
                "hits": {"aws": False, "sendgrid": False, "stripe": False},
                "phase": "failed",
            }

    # Heartbeat thread so elapsed_ms / updated_at keep moving during long jadx runs
    stop_heartbeat = threading.Event()

    def _heartbeat() -> None:
        while not stop_heartbeat.wait(2.0):
            with _STATUS_LOCK:
                if status.get("state") != "running":
                    break
                if status.get("active"):
                    _write_status(status_file, status)

    hb = threading.Thread(target=_heartbeat, name="status-heartbeat", daemon=True)
    hb.start()

    try:
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
    finally:
        stop_heartbeat.set()

    if progress is not None:
        progress.close()

    status["state"] = "completed"
    status["finished_at"] = _utc_now()
    status["active"] = {}
    status["current"] = []
    agg = aggregate_results(status["jobs"])
    # Prefer full per-apk files for final aggregation when available
    disk_jobs = []
    for path in output_dir.glob("*.json"):
        if path.name in {"status.json", "summary.json", "dashboard-config.json", "download-status.json"}:
            continue
        try:
            disk_jobs.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    if disk_jobs:
        agg = aggregate_results(disk_jobs)
    status["raw_lines"] = agg["lines"]
    status["priority_lines"] = agg.get("priority_lines") or []
    status["other_lines"] = agg.get("other_lines") or []
    status["aws_pairs"] = agg["aws_pairs"]
    (output_dir / "results.txt").write_text(agg["text"], encoding="utf-8")
    (output_dir / "priority-results.txt").write_text(agg.get("priority_text") or "", encoding="utf-8")
    (output_dir / "other-results.txt").write_text(agg.get("other_text") or "", encoding="utf-8")
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
            threads=max(1, min(32, args.threads)),
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
