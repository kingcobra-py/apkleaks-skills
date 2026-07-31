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
import shlex
import shutil
import signal
import subprocess
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

from admin_sdk_detect import detect_admin_sdk, merge_admin_sdk  # noqa: E402
from db_url_detect import detect_db_urls, merge_db_urls  # noqa: E402
from firebase_probe import (  # noqa: E402
    build_firebase_summary,
    hosts_from_job,
    merge_firebase_results,
    probe_job,
    write_firebase_summary,
)
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

# Only scan text-ish decompiled sources — skipping binaries/resources is a large speedup.
_SCAN_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".xml",
    ".smali",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".properties",
    ".txt",
    ".yml",
    ".yaml",
    ".gradle",
    ".html",
    ".htm",
    ".css",
    ".proto",
    ".plist",
    ".cfg",
    ".ini",
    ".env",
    ".sql",
    ".md",
}
_SKIP_DIR_PARTS = (
    "/androidx/",
    "/kotlin/",
    "/kotlinx/",
    "/okhttp3/",
    "/okio/",
    "/retrofit2/",
    "/com/google/android/",
    "/com/google/gson/",
    "/com/google/protobuf/",
    "/org/apache/",
    "/org/intellij/",
    "/org/jetbrains/",
    "/META-INF/",
    "/res/drawable",
    "/res/mipmap",
    "/res/raw/",
    "/assets/fonts/",
)
_MAX_SCAN_FILE_BYTES = 800_000
_MAX_JS_SCAN_FILE_BYTES = 200_000
_JADX_TIMEOUT_SEC = 240
# Hard wall-clock limit per APK (subprocess kill). Prevents 3h+ stuck workers.
_APK_TIMEOUT_SEC = 900
# Cooperative deadline for the regex pass inside a worker.
_SCAN_PHASE_TIMEOUT_SEC = 600
# Bail out of a single huge/minified file after this many seconds of matching.
_PER_FILE_BUDGET_SEC = 2.5
_MINIFIED_EXTS = {".js", ".jsx", ".ts", ".tsx", ".css", ".html", ".htm", ".json"}

# Patterns that are expensive and low-value for batch high-severity secret hunting.
_SKIP_PATTERN_NAMES = {
    "LinkFinder",
    "IP_Address",
    "IPv4",
    "IPv6",
    "Mac_Address",
    "Mailto",
    "Email",
    "URL",
    "DEFCON_CTF_Flag",
    "HackerOne_CTF_Flag",
    "HackTheBox_CTF_Flag",
    "TryHackMe_CTF_Flag",
    # Broad / catastrophic on minified bundles — low signal for secret hunting.
    "Password_in_URL",
    "Generic_Password",
}


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
            "firebase_dumpable": 0,
            "admin_sdk": 0,
            "db_urls": 0,
        },
        "current": [],
        "active": {},  # apk -> live phase info
        "jobs": [],
        "logs": [],
        "raw_lines": [],
        "priority_lines": [],
        "other_lines": [],
        "aws_pairs": [],
        "firebase_access": [],
        "admin_sdk": [],
        "db_urls": [],
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
    # Unique temp name — two batch_scan processes used to race on status.tmp
    # and crash the heartbeat with FileNotFoundError.
    tmp = path.with_name(f"{path.stem}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        LOG.warning("Failed to write status %s: %s", path, exc)
        try:
            tmp.unlink(missing_ok=True)  # type: ignore[call-arg]
        except TypeError:
            # Python <3.8 compat / older pathlib
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        except OSError:
            pass


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
        "firebase": "Firebase" in names,
    }


def _slim_job(job: dict[str, Any]) -> dict[str, Any]:
    """Keep status.json small — full findings stay in per-APK JSON files."""
    firebase = job.get("firebase_access") or []
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
        "firebase_access": firebase,
        "firebase_dumpable": sum(1 for r in firebase if r.get("dumpable")),
        "admin_sdk": job.get("admin_sdk") or [],
        "db_urls": job.get("db_urls") or [],
        "hits": job.get("hits") or {},
        "phase": job.get("phase") or ("done" if job.get("ok") else "failed"),
    }


def _compile_pattern_rules(
    pattern_path: str | Path,
    severity: str | None = None,
) -> list[tuple[str, re.Pattern[str]]]:
    """Load regex JSON into (name, compiled) pairs. List values expand to multiple rules."""
    with open(pattern_path, encoding="utf-8") as handle:
        regex = json.load(handle)

    sev_rank: int | None = None
    severity_map: dict[str, str] = {}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if severity:
        try:
            cli = _load_cli()
            severity_map = getattr(cli, "SEVERITY_MAP", {}) or {}
            severity_order = getattr(cli, "SEVERITY_ORDER", severity_order) or severity_order
            sev_rank = severity_order.get(severity)
        except Exception:  # noqa: BLE001
            sev_rank = severity_order.get(severity)

    compiled: list[tuple[str, re.Pattern[str]]] = []
    for name, pattern in regex.items():
        if name in _SKIP_PATTERN_NAMES:
            continue
        if sev_rank is not None:
            cat_sev = severity_map.get(name, "medium")
            if severity_order.get(cat_sev, 3) > sev_rank:
                continue
        patterns = pattern if isinstance(pattern, list) else [pattern]
        for p in patterns:
            if not isinstance(p, str) or not p:
                continue
            try:
                compiled.append((name, re.compile(p)))
            except re.error:
                LOG.warning("Skipping invalid regex for %s", name)
    return compiled


def _should_scan_file(path: str) -> bool:
    lower = path.replace("\\", "/")
    for part in _SKIP_DIR_PARTS:
        if part in lower:
            return False
    # Bundled web assets are usually minified and dominate scan time.
    if "/assets/" in lower and os.path.splitext(lower)[1] in _MINIFIED_EXTS:
        # Still allow small config-ish JSON under assets.
        if lower.endswith(".json"):
            try:
                if os.path.getsize(path) <= 64_000:
                    return True
            except OSError:
                return False
        return False
    ext = os.path.splitext(lower)[1]
    if ext in _SCAN_EXTENSIONS:
        return True
    # Small extensionless text files (rare) — skip by default.
    return False


def _max_bytes_for_path(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    if ext in _MINIFIED_EXTS:
        return _MAX_JS_SCAN_FILE_BYTES
    return _MAX_SCAN_FILE_BYTES


def _looks_minified(data: str, path: str) -> bool:
    """Detect webpack/minified bundles that make regex matching pathological."""
    if len(data) < 40_000:
        return False
    ext = os.path.splitext(path)[1].lower()
    if ext not in _MINIFIED_EXTS and ext not in {".java", ".xml"}:
        return False
    newlines = data.count("\n")
    if newlines <= 5 and len(data) >= 40_000:
        return True
    if newlines > 0 and (len(data) / newlines) >= 800:
        return True
    return False


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
    severity: str | None = None,
    deadline: float | None = None,
) -> list[dict[str, Any]]:
    """Single-pass secret scan: walk each file once, apply all patterns.

    Upstream APKLeaks.scanning() walks the whole tree once per regex (~95 full
    passes), which looks frozen at a fixed UI percent for many minutes.
    """
    rules = _compile_pattern_rules(pattern_path, severity=severity)
    files: list[str] = []
    for fp, dirnames, fnames in os.walk(tempdir):
        # Prune heavy vendor trees in-place.
        dirnames[:] = [
            d
            for d in dirnames
            if d
            not in {
                "androidx",
                "kotlin",
                "kotlinx",
                "okhttp3",
                "okio",
                "META-INF",
                "node_modules",
                "webpack",
            }
        ]
        for fn in fnames:
            filepath = os.path.join(fp, fn)
            if _should_scan_file(filepath):
                files.append(filepath)

    found: dict[str, set[str]] = {}
    total = len(files)
    last_report = 0
    report_every = max(1, total // 40) if total else 1
    timed_out = False

    if on_progress:
        on_progress(0, total)

    for idx, filepath in enumerate(files, 1):
        if deadline is not None and time.time() >= deadline:
            timed_out = True
            if on_progress:
                on_progress(idx, total)
            break
        try:
            size = os.path.getsize(filepath)
            max_bytes = _max_bytes_for_path(filepath)
            if size <= 0 or size > max_bytes:
                pass
            else:
                with open(filepath, encoding="utf-8", errors="ignore") as handle:
                    data = handle.read()
                if data and not _looks_minified(data, filepath):
                    file_deadline = time.time() + _PER_FILE_BUDGET_SEC
                    for name, matcher in rules:
                        if time.time() >= file_deadline:
                            break
                        if deadline is not None and time.time() >= deadline:
                            timed_out = True
                            break
                        for mo in matcher.finditer(data):
                            secret = mo.group()
                            if name == "LinkFinder":
                                secret = _filter_linkfinder_secret(secret)
                                if secret is None:
                                    continue
                            found.setdefault(name, set()).add(secret)
                        if timed_out:
                            break
        except OSError:
            pass

        if on_progress and (idx == total or idx - last_report >= report_every):
            last_report = idx
            on_progress(idx, total)
        if timed_out:
            break

    if timed_out:
        LOG.warning(
            "Scan phase hit deadline after %s/%s files under %s",
            last_report or 0,
            total,
            tempdir,
        )

    results: list[dict[str, Any]] = []
    for name, matches in found.items():
        if matches:
            results.append({"name": name, "matches": sorted(matches)})
    return results


def _decompile_with_timeout(runner: Any, timeout_sec: int = _JADX_TIMEOUT_SEC) -> None:
    """Run jadx with a hard timeout — upstream os.system() can hang forever."""
    args = [runner.jadx, runner.file, "-d", runner.tempdir]
    disarg = getattr(runner, "disarg", None)
    if disarg:
        try:
            args.extend(shlex.split(str(disarg)))
        except ValueError:
            args.extend(re.split(r"\s|=", str(disarg)))
    # Drop empty tokens from naive splits
    args = [a for a in args if a]
    LOG.info("jadx timeout=%ss cmd=%s", timeout_sec, " ".join(args[:6]))
    try:
        proc = subprocess.run(
            args,
            timeout=timeout_sec,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if proc.returncode not in (0, 1):
            # jadx often returns 1 when some classes fail — still usable output.
            LOG.warning("jadx exited with code %s for %s", proc.returncode, runner.file)
    except subprocess.TimeoutExpired as exc:
        # Ensure hung jadx trees are killed.
        try:
            if exc.process is not None:
                exc.process.kill()
        except Exception:  # noqa: BLE001
            pass
        raise TimeoutError(f"jadx timed out after {timeout_sec}s") from exc


def _fast_scanning(
    runner: Any,
    on_progress: Callable[[int, int], None] | None = None,
    severity: str | None = None,
    deadline: float | None = None,
) -> None:
    """Replace runner.scanning() with single-pass walk + live progress."""
    package = ""
    apk_obj = getattr(runner, "apk", None)
    if apk_obj is not None:
        package = getattr(apk_obj, "package", "") or ""
    runner.out_json["package"] = package
    runner.out_json["results"] = []
    results = fast_scan_tempdir(
        runner.tempdir,
        runner.pattern,
        on_progress=on_progress,
        severity=severity,
        deadline=deadline,
    )
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
            "firebase_access": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False, "firebase": False},
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
        _decompile_with_timeout(runner)

        def on_scan_progress(done: int, total: int) -> None:
            pct = _scan_percent(done, total)
            if total <= 0:
                phase("scanning", "No decompiled files to scan", pct)
            else:
                phase("scanning", f"Scanning files {done}/{total}", pct)

        phase("scanning", "Matching secret patterns (single pass)", SCAN_PCT_START)
        # Single-pass walk — upstream scanning() re-walks the tree per regex and
        # freezes the UI at a fixed percent for a very long time.
        scan_deadline = time.time() + _SCAN_PHASE_TIMEOUT_SEC
        _fast_scanning(
            runner,
            on_progress=on_scan_progress,
            severity=severity,
            deadline=scan_deadline,
        )

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
        norm = normalize_job_findings({
            "findings": findings,
            "apk": apk.name,
            "package": classified.get("package") or "",
        })
        admin_sdk = list(norm.get("admin_sdk") or [])
        if not admin_sdk:
            try:
                admin_sdk = detect_admin_sdk({
                    "apk": apk.name,
                    "package": classified.get("package") or "",
                    "findings": findings,
                    "raw_lines": norm["raw_lines"],
                    "priority_lines": norm["priority_lines"],
                    "other_lines": norm["other_lines"],
                })
            except Exception as exc:  # noqa: BLE001
                LOG.warning("Admin SDK detect failed for %s: %s", apk.name, exc)
                admin_sdk = []
        if any(h.get("severity") in ("critical", "high") for h in admin_sdk):
            hits["admin_sdk"] = True
        db_urls = list(norm.get("db_urls") or [])
        if not db_urls:
            try:
                db_urls = detect_db_urls({
                    "apk": apk.name,
                    "package": classified.get("package") or "",
                    "findings": findings,
                    "raw_lines": norm["raw_lines"],
                    "priority_lines": norm["priority_lines"],
                    "other_lines": norm["other_lines"],
                })
            except Exception as exc:  # noqa: BLE001
                LOG.warning("DB URL detect failed for %s: %s", apk.name, exc)
                db_urls = []
        if any(h.get("severity") in ("critical", "high") for h in db_urls):
            hits["db_urls"] = True
        firebase_access: list[dict[str, Any]] = []
        probe_input = {
            "apk": apk.name,
            "package": classified.get("package") or "",
            "findings": findings,
            "raw_lines": norm["raw_lines"],
            "other_lines": norm["other_lines"],
            "priority_lines": norm["priority_lines"],
        }
        if hosts_from_job(probe_input):
            phase("firebase", "Probing Firebase DB read access", 96)
            try:
                firebase_access = probe_job(probe_input)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("Firebase probe failed for %s: %s", apk.name, exc)
                firebase_access = []
            if any(r.get("dumpable") for r in firebase_access):
                hits["firebase_dumpable"] = True
        duration_ms = int((time.time() - started) * 1000)
        error_code = "NO_FINDINGS" if classified.get("total_findings", 0) == 0 else None
        dumpable_n = sum(1 for r in firebase_access if r.get("dumpable"))
        admin_n = sum(1 for h in admin_sdk if h.get("severity") in ("critical", "high"))
        db_n = sum(1 for h in db_urls if h.get("severity") in ("critical", "high"))
        phase(
            "done",
            f"Done — {norm['finding_count']} secret(s)"
            + (f", {dumpable_n} dumpable Firebase" if dumpable_n else "")
            + (f", {admin_n} Admin SDK" if admin_n else "")
            + (f", {db_n} DB URL" if db_n else ""),
        )
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
            "admin_sdk": admin_sdk,
            "db_urls": db_urls,
            "firebase_access": firebase_access,
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
            "firebase_access": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False, "firebase": False},
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
            "firebase_access": [],
            "hits": {"aws": False, "sendgrid": False, "stripe": False, "firebase": False},
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


def _empty_failed_job(
    apk: Path,
    error: str,
    error_code: str = "SCAN_FAILED",
    duration_ms: int = 0,
) -> dict[str, Any]:
    return {
        "apk": apk.name,
        "path": str(apk),
        "ok": False,
        "error": error,
        "error_code": error_code,
        "duration_ms": duration_ms,
        "has_critical": False,
        "finding_count": 0,
        "findings": [],
        "raw_lines": [],
        "priority_lines": [],
        "other_lines": [],
        "aws_pairs": [],
        "firebase_access": [],
        "hits": {"aws": False, "sendgrid": False, "stripe": False, "firebase": False},
        "phase": "failed",
    }


def _kill_process_tree(proc: subprocess.Popen[Any]) -> None:
    """Best-effort kill of a worker process group (jadx children included)."""
    try:
        if proc.pid:
            os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


def run_one_apk(
    apk: Path,
    severity: str | None,
    pattern: str | None,
    jadx_args: str | None,
    out_path: Path,
    progress_path: Path | None = None,
) -> dict[str, Any]:
    """Scan a single APK in this process and write the result JSON."""

    def on_phase(phase: str, message: str, percent: int | None = None) -> None:
        if progress_path is None:
            return
        payload = {
            "apk": apk.name,
            "phase": phase,
            "message": message,
            "percent": percent,
            "updated_at": _utc_now(),
        }
        try:
            progress_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(progress_path)
        except OSError:
            pass

    job = _scan_one(apk, severity, pattern, jadx_args, on_phase=on_phase)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(job, indent=2), encoding="utf-8")
    except OSError as exc:
        LOG.warning("Failed to write one-apk result for %s: %s", apk.name, exc)
    return job


def _scan_apk_subprocess(
    apk: Path,
    *,
    severity: str | None,
    pattern: str | None,
    jadx_args: str | None,
    output_dir: Path,
    timeout_sec: int,
    on_phase: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Run one APK in an isolated subprocess so hung regex/jadx can be killed."""
    out_path = output_dir / f"{apk.stem}.json"
    progress_path = output_dir / f".progress-{apk.stem}.json"
    script = str(Path(__file__).resolve())
    cmd = [
        sys.executable,
        script,
        "--one",
        str(apk),
        "--one-out",
        str(out_path),
        "--one-progress",
        str(progress_path),
    ]
    if severity:
        cmd.extend(["-s", severity])
    if pattern:
        cmd.extend(["-p", pattern])
    if jadx_args:
        cmd.extend(["-a", jadx_args])

    started = time.time()
    try:
        if progress_path.is_file():
            progress_path.unlink()
    except OSError:
        pass

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return _empty_failed_job(apk, f"Failed to spawn worker: {exc}")

    last_progress_read = 0.0
    try:
        while True:
            rc = proc.poll()
            now = time.time()
            if on_phase and now - last_progress_read >= 0.75 and progress_path.is_file():
                last_progress_read = now
                try:
                    prog = json.loads(progress_path.read_text(encoding="utf-8"))
                    on_phase(
                        str(prog.get("phase") or "scanning"),
                        str(prog.get("message") or "Scanning"),
                        prog.get("percent"),
                    )
                except (OSError, json.JSONDecodeError, TypeError, ValueError):
                    pass
            if rc is not None:
                break
            if now - started >= timeout_sec:
                _kill_process_tree(proc)
                duration_ms = int((time.time() - started) * 1000)
                if on_phase:
                    on_phase("failed", f"Timed out after {timeout_sec}s", 100)
                return _empty_failed_job(
                    apk,
                    f"Timed out after {timeout_sec}s",
                    error_code="TIMEOUT",
                    duration_ms=duration_ms,
                )
            time.sleep(0.5)
    finally:
        if proc.poll() is None:
            _kill_process_tree(proc)
        try:
            if progress_path.is_file():
                progress_path.unlink()
        except OSError:
            pass

    duration_ms = int((time.time() - started) * 1000)
    if out_path.is_file():
        try:
            job = json.loads(out_path.read_text(encoding="utf-8"))
            if isinstance(job, dict) and "apk" in job:
                job.setdefault("duration_ms", duration_ms)
                return job
        except (OSError, json.JSONDecodeError) as exc:
            return _empty_failed_job(
                apk,
                f"Invalid worker result: {exc}",
                duration_ms=duration_ms,
            )
    return _empty_failed_job(
        apk,
        f"Worker exited with code {proc.returncode} and no result file",
        duration_ms=duration_ms,
    )


def run_batch(
    input_dir: Path,
    output_dir: Path,
    threads: int = 4,
    severity: str | None = "high",
    pattern: str | None = None,
    jadx_args: str | None = None,
    status_path: Path | None = None,
    apk_timeout: int = _APK_TIMEOUT_SEC,
) -> dict[str, Any]:
    apks = discover_apks(input_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    status_file = status_path or (output_dir / "status.json")

    # Resume: skip APKs that already have a successful result JSON.
    pending: list[Path] = []
    skipped_done = 0
    for apk in apks:
        result_path = output_dir / f"{apk.stem}.json"
        if result_path.is_file():
            try:
                prev = json.loads(result_path.read_text(encoding="utf-8"))
                if isinstance(prev, dict) and prev.get("ok") is True:
                    skipped_done += 1
                    continue
            except json.JSONDecodeError:
                pass
        pending.append(apk)
    apks = pending

    status = _empty_status(len(apks), threads, str(input_dir), str(output_dir))
    status["progress"]["skipped_done"] = skipped_done
    # Keep previously found secrets visible while a new scan starts.
    try:
        seed_jobs: list[tuple[float, dict[str, Any]]] = []
        for path in output_dir.glob("*.json"):
            if path.name in {"status.json", "summary.json", "dashboard-config.json", "download-status.json"}:
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
                seed_jobs.append((mtime, job))
        seed_jobs.sort(key=lambda item: item[0], reverse=True)
        ordered_seed = [job for _, job in seed_jobs]
        if ordered_seed:
            seeded = aggregate_results(ordered_seed)
            status["priority_lines"] = seeded.get("priority_lines") or []
            status["other_lines"] = seeded.get("other_lines") or []
            status["raw_lines"] = seeded.get("lines") or []
            status["aws_pairs"] = seeded.get("aws_pairs") or []
            status["counts"]["findings"] = len(status["raw_lines"])
            status["counts"]["has_aws"] = len(status["aws_pairs"])
            fb_rows: list[dict[str, Any]] = []
            for job in ordered_seed:
                fb_rows.extend(job.get("firebase_access") or [])
            if fb_rows:
                merged_fb = merge_firebase_results(fb_rows)
                status["firebase_access"] = merged_fb
                status["counts"]["firebase_dumpable"] = sum(
                    1 for r in merged_fb if r.get("dumpable")
                )
            sa_rows: list[dict[str, Any]] = []
            for job in ordered_seed:
                existing = job.get("admin_sdk") or []
                if existing:
                    sa_rows.extend(existing)
                else:
                    try:
                        sa_rows.extend(detect_admin_sdk(job))
                    except Exception:  # noqa: BLE001
                        pass
            if sa_rows:
                merged_sa = merge_admin_sdk(sa_rows)
                status["admin_sdk"] = merged_sa
                status["counts"]["admin_sdk"] = sum(
                    1 for r in merged_sa if r.get("severity") in ("critical", "high")
                )
            db_rows: list[dict[str, Any]] = []
            for job in ordered_seed:
                existing = job.get("db_urls") or []
                if existing:
                    db_rows.extend(existing)
                else:
                    try:
                        db_rows.extend(detect_db_urls(job))
                    except Exception:  # noqa: BLE001
                        pass
            if db_rows:
                merged_db = merge_db_urls(db_rows)
                status["db_urls"] = merged_db
                status["counts"]["db_urls"] = sum(
                    1 for r in merged_db if r.get("severity") in ("critical", "high")
                )
    except Exception:  # noqa: BLE001
        pass
    status["queue_preview"] = [p.name for p in apks[:50]]
    _append_log(
        status,
        "info",
        f"Discovered work: {len(apks)} pending, {skipped_done} already scanned; threads={threads}",
    )
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
            # Terminal phases should not linger in the live "active" map — otherwise
            # the UI fills with finished apps when mark_done falls behind or crashes.
            if phase in ("done", "failed"):
                status["active"].pop(name, None)
                if name in status["current"]:
                    status["current"].remove(name)
                # Still bump updated_at so the dashboard knows work is moving.
                status["updated_at"] = _utc_now()
                _write_status(status_file, status)
                return

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
            if name not in status["current"]:
                status["current"].append(name)
            # Throttle disk writes during dense scanning progress updates.
            changed = (
                phase != prev_phase
                or message != prev_msg
                or prev_pct is None
                or abs(pct - int(prev_pct)) >= 2
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
        # Mutate status under the lock, but do NOT hold the lock while writing
        # large result files — that starved workers and left dozens of APKs
        # stuck as phase=done in the UI with no further progress.
        export_payload: dict[str, str] | None = None
        firebase_snapshot: list[dict[str, Any]] | None = None
        with _STATUS_LOCK:
            name = job["apk"]
            if name in status["current"]:
                status["current"].remove(name)
            status["active"].pop(name, None)
            slim = _slim_job(job)
            status["jobs"].append(slim)
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
            new_other = [
                line
                for line in (job.get("other_lines") or [])
                if line
                and line not in status["other_lines"]
                and line not in status["priority_lines"]
            ]
            if new_other:
                status["other_lines"] = new_other + list(status["other_lines"])
            # Cap exported other lines so status writes stay cheap.
            if len(status["other_lines"]) > 2000:
                status["other_lines"] = status["other_lines"][:2000]
            status["raw_lines"] = list(status["priority_lines"]) + list(status["other_lines"])
            for pair in job.get("aws_pairs") or []:
                if pair not in status["aws_pairs"]:
                    status["aws_pairs"].append(pair)
            if job.get("firebase_access"):
                merged = merge_firebase_results(
                    list(status.get("firebase_access") or []) + list(job.get("firebase_access") or [])
                )
                status["firebase_access"] = merged
                status["counts"]["firebase_dumpable"] = sum(1 for r in merged if r.get("dumpable"))
                status["counts"]["firebase_emails"] = sum(
                    int(r.get("email_count") or 0) for r in merged
                )
                firebase_snapshot = list(merged)
            if job.get("admin_sdk"):
                merged_sa = merge_admin_sdk(
                    list(status.get("admin_sdk") or []) + list(job.get("admin_sdk") or [])
                )
                status["admin_sdk"] = merged_sa
                status["counts"]["admin_sdk"] = sum(
                    1 for r in merged_sa if r.get("severity") in ("critical", "high")
                )
            if job.get("db_urls"):
                merged_db = merge_db_urls(
                    list(status.get("db_urls") or []) + list(job.get("db_urls") or [])
                )
                status["db_urls"] = merged_db
                status["counts"]["db_urls"] = sum(
                    1 for r in merged_db if r.get("severity") in ("critical", "high")
                )
            level = "info" if job["ok"] else "error"
            dumpable_n = sum(1 for r in (job.get("firebase_access") or []) if r.get("dumpable"))
            admin_n = sum(
                1 for r in (job.get("admin_sdk") or []) if r.get("severity") in ("critical", "high")
            )
            db_n = sum(
                1 for r in (job.get("db_urls") or []) if r.get("severity") in ("critical", "high")
            )
            msg = (
                f"Done {job['apk']}: findings={job.get('finding_count', 0)} "
                f"ok={job['ok']} ({job.get('duration_ms', 0)} ms)"
                + (f" firebase_dumpable={dumpable_n}" if dumpable_n else "")
                + (f" admin_sdk={admin_n}" if admin_n else "")
                + (f" db_urls={db_n}" if db_n else "")
            )
            _append_log(status, level, msg)
            LOG.log(logging.INFO if job["ok"] else logging.ERROR, msg)
            export_payload = {
                "raw": "\n".join(status["raw_lines"]) + ("\n" if status["raw_lines"] else ""),
                "priority": "\n".join(status["priority_lines"])
                + ("\n" if status["priority_lines"] else ""),
                "other": "\n".join(status["other_lines"]) + ("\n" if status["other_lines"] else ""),
            }
            _write_status(status_file, status)

        if export_payload is not None:
            try:
                out_dir = status_file.parent
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "results.txt").write_text(export_payload["raw"], encoding="utf-8")
                (out_dir / "priority-results.txt").write_text(export_payload["priority"], encoding="utf-8")
                (out_dir / "other-results.txt").write_text(export_payload["other"], encoding="utf-8")
            except OSError as exc:
                LOG.warning("Failed to write export txt files: %s", exc)

        # Persist Firebase access live so the dashboard updates without a manual probe click.
        if firebase_snapshot is not None:
            try:
                write_firebase_summary(
                    output_dir,
                    firebase_snapshot,
                    message="Live — probed during APK scan (newest first)",
                )
            except OSError as exc:
                LOG.warning("Failed to write firebase-access.json: %s", exc)

    def _worker(apk: Path) -> dict[str, Any]:
        mark_start(apk.name)

        def on_phase(phase: str, message: str, percent: int | None = None) -> None:
            set_phase(apk.name, phase, message, percent)

        try:
            # Isolated subprocess so a pathological regex/jadx hang can be SIGKILL'd
            # after apk_timeout — in-thread workers were stuck for hours.
            return _scan_apk_subprocess(
                apk,
                severity=severity,
                pattern=pattern,
                jadx_args=jadx_args,
                output_dir=output_dir,
                timeout_sec=max(60, int(apk_timeout)),
                on_phase=on_phase,
            )
        except Exception as exc:  # noqa: BLE001
            set_phase(apk.name, "failed", str(exc)[:120])
            return _empty_failed_job(apk, str(exc))

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
                try:
                    job = fut.result()
                except Exception as exc:  # noqa: BLE001
                    job = {
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
                        "firebase_access": [],
                        "hits": {"aws": False, "sendgrid": False, "stripe": False, "firebase": False},
                        "phase": "failed",
                    }
                    set_phase(apk.name, "failed", str(exc)[:120])
                try:
                    (output_dir / f"{apk.stem}.json").write_text(
                        json.dumps(job, indent=2),
                        encoding="utf-8",
                    )
                except OSError as exc:
                    LOG.warning("Failed to write per-APK JSON for %s: %s", apk.name, exc)
                try:
                    mark_done(job)
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("mark_done failed for %s: %s", apk.name, exc)
                    with _STATUS_LOCK:
                        status["active"].pop(apk.name, None)
                        if apk.name in status["current"]:
                            status["current"].remove(apk.name)
                        status["progress"]["completed"] += 1
                        status["progress"]["failed"] += 1
                        _write_status(status_file, status)
                if progress is not None:
                    progress.update(1)
                    progress.set_postfix(
                        ok=status["progress"]["succeeded"],
                        fail=status["progress"]["failed"],
                        findings=status["counts"]["findings"],
                    )
    finally:
        stop_heartbeat.set()
        with _STATUS_LOCK:
            # Clear any leftover active entries so the UI never sticks on finished apps.
            status["active"] = {}
            status["current"] = []
            _write_status(status_file, status)

    if progress is not None:
        progress.close()

    status["state"] = "completed"
    status["finished_at"] = _utc_now()
    status["active"] = {}
    status["current"] = []
    agg = aggregate_results(list(reversed(status["jobs"])))
    # Prefer full per-apk files for final aggregation when available (newest first).
    disk_jobs: list[tuple[float, dict[str, Any]]] = []
    for path in output_dir.glob("*.json"):
        if path.name in {"status.json", "summary.json", "dashboard-config.json", "download-status.json"}:
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
            disk_jobs.append((mtime, job))
    if disk_jobs:
        disk_jobs.sort(key=lambda item: item[0], reverse=True)
        agg = aggregate_results([job for _, job in disk_jobs])
    status["raw_lines"] = agg["lines"]
    status["priority_lines"] = agg.get("priority_lines") or []
    status["other_lines"] = agg.get("other_lines") or []
    status["aws_pairs"] = agg["aws_pairs"]
    # Persist Firebase probe summary from per-APK results (already probed during scan).
    try:
        fb_rows: list[dict[str, Any]] = []
        for _, job in disk_jobs:
            fb_rows.extend(job.get("firebase_access") or [])
        if not fb_rows:
            for job in status.get("jobs") or []:
                fb_rows.extend(job.get("firebase_access") or [])
        if fb_rows:
            summary_fb = build_firebase_summary(
                fb_rows,
                message="Batch complete — Firebase hosts auto-probed (newest first)",
            )
            status["firebase_access"] = summary_fb["results"]
            status["counts"]["firebase_dumpable"] = summary_fb["dumpable_count"]
            status["counts"]["firebase_emails"] = int(summary_fb.get("email_count") or 0)
            (output_dir / "firebase-access.json").write_text(
                json.dumps(summary_fb, indent=2),
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Failed to write firebase-access.json: %s", exc)
    try:
        sa_rows: list[dict[str, Any]] = []
        for _, job in disk_jobs:
            existing = job.get("admin_sdk") or []
            if existing:
                sa_rows.extend(existing)
            else:
                sa_rows.extend(detect_admin_sdk(job))
        if sa_rows:
            merged_sa = merge_admin_sdk(sa_rows)
            status["admin_sdk"] = merged_sa
            status["counts"]["admin_sdk"] = sum(
                1 for r in merged_sa if r.get("severity") in ("critical", "high")
            )
            (output_dir / "admin-sdk-access.json").write_text(
                json.dumps({
                    "ok": True,
                    "total": len(merged_sa),
                    "critical_count": sum(1 for r in merged_sa if r.get("severity") == "critical"),
                    "high_count": sum(1 for r in merged_sa if r.get("severity") == "high"),
                    "results": merged_sa,
                    "updated_at": _utc_now(),
                }, indent=2),
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Failed to write admin-sdk-access.json: %s", exc)
    try:
        db_rows: list[dict[str, Any]] = []
        for _, job in disk_jobs:
            existing = job.get("db_urls") or []
            if existing:
                db_rows.extend(existing)
            else:
                db_rows.extend(detect_db_urls(job))
        if db_rows:
            merged_db = merge_db_urls(db_rows)
            status["db_urls"] = merged_db
            status["counts"]["db_urls"] = sum(
                1 for r in merged_db if r.get("severity") in ("critical", "high")
            )
            (output_dir / "db-urls.json").write_text(
                json.dumps({
                    "ok": True,
                    "total": len(merged_db),
                    "critical_count": sum(1 for r in merged_db if r.get("severity") == "critical"),
                    "high_count": sum(1 for r in merged_db if r.get("severity") == "high"),
                    "with_credentials": sum(1 for r in merged_db if r.get("has_credentials")),
                    "results": merged_db,
                    "updated_at": _utc_now(),
                }, indent=2),
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Failed to write db-urls.json: %s", exc)
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
    parser.add_argument("-d", "--dir", default=None, help="Directory of APK files (or a single .apk)")
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
    parser.add_argument(
        "--apk-timeout",
        type=int,
        default=_APK_TIMEOUT_SEC,
        help=f"Hard per-APK timeout seconds (default: {_APK_TIMEOUT_SEC})",
    )
    parser.add_argument("--one", default=None, help="Scan a single APK path and exit (worker mode)")
    parser.add_argument("--one-out", default=None, help="Result JSON path for --one")
    parser.add_argument("--one-progress", default=None, help="Live progress JSON path for --one")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.one:
        apk = Path(args.one)
        if not apk.is_file():
            LOG.error("APK not found: %s", apk)
            return 2
        out_path = Path(args.one_out) if args.one_out else Path(args.output) / f"{apk.stem}.json"
        progress_path = Path(args.one_progress) if args.one_progress else None
        job = run_one_apk(
            apk,
            severity=args.severity,
            pattern=args.pattern,
            jadx_args=args.jadx_args,
            out_path=out_path,
            progress_path=progress_path,
        )
        print(json.dumps({"ok": bool(job.get("ok")), "apk": job.get("apk"), "error": job.get("error")}))
        return 0 if job.get("ok") else 1

    if not args.dir:
        LOG.error("-d/--dir is required unless --one is set")
        return 2

    try:
        status = run_batch(
            input_dir=Path(args.dir),
            output_dir=Path(args.output),
            threads=max(1, min(32, args.threads)),
            severity=args.severity,
            pattern=args.pattern,
            jadx_args=args.jadx_args,
            status_path=Path(args.status) if args.status else None,
            apk_timeout=max(60, int(args.apk_timeout)),
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
