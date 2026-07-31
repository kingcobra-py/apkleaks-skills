#!/usr/bin/env python3
"""Probe Firebase Realtime Database hosts for unauthenticated read access."""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

LOG = logging.getLogger("firebase_probe")

USER_AGENT = "apkleaks-skills-firebase-probe/1.0 (+authorized security research)"
_FIREBASE_HOST_RE = re.compile(
    r"(?i)\b("
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.firebaseio\.com"
    r"|"
    r"[a-z0-9][a-z0-9.-]*\.firebasedatabase\.app"
    r")\b"
)
_GOOGLE_API_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")

# Skip known public demo / documentation hosts.
_SKIP_HOSTS = {
    "hacker-news.firebaseio.com",
    "docs-examples.firebaseio.com",
    "project-id.firebaseio.com",
    "your-project.firebaseio.com",
    "example.firebaseio.com",
}


def extract_firebase_hosts(*texts: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for m in _FIREBASE_HOST_RE.finditer(text):
            host = m.group(1).lower().rstrip(".")
            if host in _SKIP_HOSTS or host in seen:
                continue
            seen.add(host)
            found.append(host)
    return found


def extract_google_api_keys(*texts: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for m in _GOOGLE_API_KEY_RE.finditer(text):
            key = m.group(1)
            if key in seen:
                continue
            seen.add(key)
            found.append(key)
    return found


def hosts_from_job(job: dict[str, Any]) -> list[str]:
    chunks: list[str] = []
    for finding in job.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        name = str(finding.get("name") or "")
        matches = finding.get("matches") or []
        if isinstance(matches, str):
            matches = [matches]
        for m in matches:
            if isinstance(m, str):
                chunks.append(m)
            elif isinstance(m, dict):
                chunks.append(json.dumps(m))
        if "firebase" in name.lower():
            chunks.append(name)
    for key in ("raw_lines", "priority_lines", "other_lines", "package", "apk"):
        val = job.get(key)
        if isinstance(val, str):
            chunks.append(val)
        elif isinstance(val, list):
            chunks.extend(str(x) for x in val if x)
    return extract_firebase_hosts(*chunks)


def api_keys_from_job(job: dict[str, Any]) -> list[str]:
    chunks: list[str] = []
    for finding in job.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for m in finding.get("matches") or []:
            if isinstance(m, str):
                chunks.append(m)
    for key in ("raw_lines", "other_lines", "priority_lines"):
        val = job.get(key)
        if isinstance(val, list):
            chunks.extend(str(x) for x in val if x)
    return extract_google_api_keys(*chunks)


def _http_get_json(url: str, timeout: float = 10.0) -> tuple[int, Any, str]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read(2_000_000)  # cap 2MB — shallow probes are tiny
            status = getattr(resp, "status", 200) or 200
            text = raw.decode("utf-8", errors="replace")
            try:
                return int(status), json.loads(text), text
            except json.JSONDecodeError:
                return int(status), None, text
    except HTTPError as exc:
        raw = exc.read(500_000) if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", errors="replace") if raw else str(exc)
        try:
            return int(exc.code), json.loads(text), text
        except Exception:  # noqa: BLE001
            return int(exc.code), None, text
    except (URLError, TimeoutError, OSError) as exc:
        return 0, None, str(exc)


def _classify(http_status: int, payload: Any, raw_text: str) -> dict[str, Any]:
    err = ""
    if isinstance(payload, dict) and "error" in payload:
        err = str(payload.get("error") or "")
    elif payload is None and raw_text:
        err = raw_text[:300]

    err_l = err.lower()
    if "deactivated" in err_l:
        return {
            "status": "deactivated",
            "dumpable": False,
            "detail": err or "Database deactivated",
        }
    if "permission denied" in err_l or http_status in (401, 403):
        return {
            "status": "denied",
            "dumpable": False,
            "detail": err or "Permission denied",
        }
    if http_status == 404 or "not found" in err_l:
        return {
            "status": "not_found",
            "dumpable": False,
            "detail": err or "Not found",
        }
    if http_status == 0:
        return {
            "status": "error",
            "dumpable": False,
            "detail": err or "Network error",
        }
    if http_status >= 400:
        return {
            "status": "error",
            "dumpable": False,
            "detail": err or f"HTTP {http_status}",
        }

    # 2xx with JSON body and no error => unauthenticated read works.
    shallow_keys: list[str] = []
    if isinstance(payload, dict):
        shallow_keys = sorted(str(k) for k in payload.keys())[:40]
    elif isinstance(payload, list):
        shallow_keys = [f"[list len={len(payload)}]"]
    elif payload is None:
        shallow_keys = []

    has_data = bool(shallow_keys) or payload not in (None, {}, [])
    return {
        "status": "open",
        "dumpable": True,
        "detail": "Unauthenticated read allowed" + ("" if has_data else " (empty DB)"),
        "shallow_keys": shallow_keys,
        "empty": not has_data,
    }


def probe_host(
    host: str,
    api_key: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    host_n = host.strip().lower().rstrip("/")
    if host_n.startswith("https://"):
        host_n = host_n[len("https://") :]
    if host_n.startswith("http://"):
        host_n = host_n[len("http://") :]
    host_n = host_n.split("/")[0]

    base = f"https://{host_n}/.json"
    urls = [f"{base}?shallow=true"]
    if api_key:
        urls.append(f"{base}?shallow=true&auth={api_key}")

    best: dict[str, Any] | None = None
    for url in urls:
        http_status, payload, raw = _http_get_json(url, timeout=timeout)
        classified = _classify(http_status, payload, raw)
        result = {
            "host": host_n,
            "probe_url": url.split("&auth=")[0],  # don't echo full key in URL field
            "http_status": http_status,
            "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "used_api_key": bool(api_key) and "auth=" in url,
            **classified,
        }
        if best is None:
            best = result
        # Prefer dumpable / open over denied.
        if result.get("dumpable") and not best.get("dumpable"):
            best = result
        if result.get("status") == "open":
            best = result
            break
    assert best is not None
    return best


def probe_hosts(
    hosts: list[str],
    api_keys: list[str] | None = None,
    workers: int = 8,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    uniq: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        h2 = h.strip().lower()
        if not h2 or h2 in seen or h2 in _SKIP_HOSTS:
            continue
        seen.add(h2)
        uniq.append(h2)
    if not uniq:
        return []

    key = (api_keys or [None])[0]
    workers_n = max(1, min(16, int(workers or 1)))
    out: list[dict[str, Any]] = []

    def _one(host: str) -> dict[str, Any]:
        try:
            return probe_host(host, api_key=key, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return {
                "host": host,
                "status": "error",
                "dumpable": False,
                "detail": str(exc),
                "http_status": 0,
                "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

    if workers_n == 1:
        return [_one(h) for h in uniq]

    with ThreadPoolExecutor(max_workers=workers_n) as pool:
        futs = {pool.submit(_one, h): h for h in uniq}
        for fut in as_completed(futs):
            out.append(fut.result())
    out.sort(key=lambda r: (not r.get("dumpable"), r.get("status") != "open", r.get("host") or ""))
    return out


def probe_job(job: dict[str, Any], timeout: float = 10.0) -> list[dict[str, Any]]:
    hosts = hosts_from_job(job)
    if not hosts:
        return []
    keys = api_keys_from_job(job)
    results = probe_hosts(hosts, api_keys=keys, workers=min(8, len(hosts)), timeout=timeout)
    apk = job.get("apk") or ""
    pkg = job.get("package") or ""
    for row in results:
        row["apk"] = apk
        row["package"] = pkg
    return results


def collect_hosts_from_results(results_dir: Path) -> list[tuple[str, str, str]]:
    """Return list of (host, apk, package) from saved job JSON files."""
    skip = {
        "status.json",
        "summary.json",
        "dashboard-config.json",
        "download-status.json",
        "loop-status.json",
        "firebase-access.json",
    }
    rows: list[tuple[str, str, str]] = []
    seen_host_apk: set[tuple[str, str]] = set()
    if not results_dir.is_dir():
        return []
    for path in sorted(results_dir.glob("*.json")):
        if path.name in skip:
            continue
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(job, dict):
            continue
        apk = str(job.get("apk") or path.name)
        pkg = str(job.get("package") or "")
        for host in hosts_from_job(job):
            key = (host, apk)
            if key in seen_host_apk:
                continue
            seen_host_apk.add(key)
            rows.append((host, apk, pkg))
    return rows


def probe_results_dir(
    results_dir: Path,
    workers: int = 10,
    timeout: float = 10.0,
) -> dict[str, Any]:
    triples = collect_hosts_from_results(results_dir)
    hosts = sorted({h for h, _, _ in triples})
    # Attach first apk/package mapping
    host_meta: dict[str, dict[str, str]] = {}
    for host, apk, pkg in triples:
        host_meta.setdefault(host, {"apk": apk, "package": pkg})

    probed = probe_hosts(hosts, workers=workers, timeout=timeout)
    for row in probed:
        meta = host_meta.get(row["host"]) or {}
        row["apk"] = meta.get("apk") or ""
        row["package"] = meta.get("package") or ""

    dumpable = [r for r in probed if r.get("dumpable")]
    summary = {
        "ok": True,
        "probed": len(probed),
        "dumpable_count": len(dumpable),
        "open": [r for r in probed if r.get("status") == "open"],
        "denied": [r for r in probed if r.get("status") == "denied"],
        "deactivated": [r for r in probed if r.get("status") == "deactivated"],
        "other": [
            r
            for r in probed
            if r.get("status") not in ("open", "denied", "deactivated")
        ],
        "results": probed,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out_path = results_dir / "firebase-access.json"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def merge_firebase_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedupe by host; prefer dumpable/open."""
    rank = {"open": 0, "denied": 1, "deactivated": 2, "not_found": 3, "error": 4}
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").lower()
        if not host:
            continue
        prev = best.get(host)
        if prev is None:
            best[host] = row
            continue
        prev_rank = rank.get(str(prev.get("status")), 9)
        cur_rank = rank.get(str(row.get("status")), 9)
        if cur_rank < prev_rank or (row.get("dumpable") and not prev.get("dumpable")):
            best[host] = row
    out = list(best.values())
    out.sort(key=lambda r: (not r.get("dumpable"), rank.get(str(r.get("status")), 9), r.get("host") or ""))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe Firebase RTDB hosts for open read access")
    parser.add_argument("--results", default="results", help="Results directory with job JSON files")
    parser.add_argument("--host", action="append", default=[], help="Probe specific host(s)")
    parser.add_argument("-j", "--workers", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    if args.host:
        rows = probe_hosts(args.host, workers=args.workers, timeout=args.timeout)
        print(json.dumps({"ok": True, "results": rows}, indent=2))
        return 0
    summary = probe_results_dir(Path(args.results), workers=args.workers, timeout=args.timeout)
    print(json.dumps({
        "ok": summary["ok"],
        "probed": summary["probed"],
        "dumpable_count": summary["dumpable_count"],
        "updated_at": summary["updated_at"],
        "open_hosts": [r["host"] for r in summary["open"]],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
