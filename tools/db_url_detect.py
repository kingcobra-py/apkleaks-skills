#!/usr/bin/env python3
"""Detect database URLs / connection strings from APK scan findings."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any

DB_FINDING_NAMES = {
    "PostgreSQL_URI",
    "MySQL_URI",
    "MongoDB_URI",
    "Redis_URI",
    "JDBC_URI",
    "MSSQL_URI",
    "AMQP_URI",
    "CouchDB_URI",
    "Elasticsearch_URL",
    "Database_URL",
    "Supabase_URL",
    "AWS_RDS_Host",
    "Azure_Cosmos_Host",
    "DB_Password_Assignment",
    "Firebase",
    "Firebase_Database_App",
}

_EXTRACTORS: list[tuple[str, re.Pattern[str]]] = [
    ("mongodb", re.compile(r"(?i)\b(mongodb(?:\+srv)?://[^\s\"'<>]+)")),
    ("postgres", re.compile(r"(?i)\b((?:postgres(?:ql)?)://[^\s\"'<>]+)")),
    ("mysql", re.compile(r"(?i)\b(mysql://[^\s\"'<>]+)")),
    ("redis", re.compile(r"(?i)\b(rediss?://[^\s\"'<>]+)")),
    ("jdbc", re.compile(r"(?i)\b(jdbc:(?:mysql|postgresql|mariadb|sqlserver|oracle)://[^\s\"'<>]+)")),
    ("mssql", re.compile(r"(?i)\b((?:mssql|sqlserver)://[^\s\"'<>]+)")),
    ("amqp", re.compile(r"(?i)\b(amqps?://[^\s\"'<>]+)")),
    ("couchdb", re.compile(r"(?i)\b((?:couch(?:db)?|cloudant)://[^\s\"'<>]+)")),
    ("elasticsearch", re.compile(
        r"(?i)\b((?:https?://)?[a-z0-9.-]+\.(?:es\.[a-z0-9.-]+\.amazonaws\.com|cloud\.es\.io)[^\s\"'<>]*)"
    )),
    ("database_url", re.compile(
        r"(?i)\b((?:DATABASE_URL|DB_URL)\s*[=:]\s*['\"]?[^\\s\"']{8,})"
    )),
    ("supabase", re.compile(
        r"(?i)\b(https?://[a-z0-9-]+\.supabase\.(?:co|in|com)(?:/[^\s\"'<>]*)?)"
    )),
    ("aws_rds", re.compile(r"(?i)\b([a-z0-9][a-z0-9.-]*\.rds\.amazonaws\.com)\b")),
    ("azure_cosmos", re.compile(r"(?i)\b([a-z0-9][a-z0-9.-]*\.documents\.azure\.com)\b")),
    ("firebase", re.compile(
        r"(?i)\b([a-z0-9][a-z0-9.-]*\.(?:firebaseio\.com|firebasedatabase\.app))\b"
    )),
    ("db_password", re.compile(
        r"(?i)\b((?:db_password|database_password|mysql_password|postgres_password|"
        r"sql_password|redis_password|mongo(?:db)?_password)\s*[=:]\s*['\"][^'\"]{4,256}['\"])"
    )),
]

_LOCAL = ("localhost", "127.0.0.1", "0.0.0.0", "10.0.2.2", "::1")
_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:"
    r"@example\.com\b|"
    r"//(?:user|username|xxx+):(?:pass|password|xxx+)@|"
    r"\byour-[a-z0-9-]+\b|"
    r"\bchangeme\b|"
    r"<[^>]+>|"
    r"\bxxx+\b"
    r")"
)


def _chunks_from_job(job: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for finding in job.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        name = str(finding.get("name") or "")
        for m in finding.get("matches") or []:
            if isinstance(m, str) and m.strip():
                out.append((name, m.strip()))
    for key in ("priority_lines", "other_lines", "raw_lines"):
        for item in job.get(key) or []:
            if isinstance(item, str) and item.strip():
                out.append(("", item.strip()))
    return out


def redact_db_secret(value: str) -> str:
    """Mask password segments in URIs / assignments for safe UI display."""
    text = value.strip()
    # DATABASE_URL=postgres://user:pass@host → keep scheme/user/host, mask pass
    text = re.sub(
        r"(?i)\b((?:DATABASE_URL|DB_URL)\s*[=:]\s*)",
        r"\1",
        text,
    )
    # scheme://user:password@host
    text = re.sub(
        r"(?i)(://[^:/@\s\"']+):([^@/\s\"']+)@",
        r"\1:***@",
        text,
    )
    # jdbc may use user= / password=
    text = re.sub(
        r"(?i)([?&;]password=)([^&\s\"']+)",
        r"\1***",
        text,
    )
    # assignment passwords
    text = re.sub(
        r"(?i)((?:db_password|database_password|mysql_password|postgres_password|"
        r"sql_password|redis_password|mongo(?:db)?_password)\s*[=:]\s*['\"])([^'\"]+)(['\"])",
        r"\1***\3",
        text,
    )
    if len(text) > 220:
        text = text[:217] + "..."
    return text


def _has_embedded_credentials(value: str) -> bool:
    if re.search(r"(?i)://[^:/@\s]+:[^@/\s]+@", value):
        return True
    if re.search(r"(?i)[?&;]password=", value):
        return True
    if re.search(r"(?i)(?:db_password|database_password|mysql_password|postgres_password|sql_password)\s*[=:]", value):
        return True
    return False


def _is_local(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in _LOCAL)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value))


def _kind_from_finding_name(name: str) -> str | None:
    mapping = {
        "PostgreSQL_URI": "postgres",
        "MySQL_URI": "mysql",
        "MongoDB_URI": "mongodb",
        "Redis_URI": "redis",
        "JDBC_URI": "jdbc",
        "MSSQL_URI": "mssql",
        "AMQP_URI": "amqp",
        "CouchDB_URI": "couchdb",
        "Elasticsearch_URL": "elasticsearch",
        "Database_URL": "database_url",
        "Supabase_URL": "supabase",
        "AWS_RDS_Host": "aws_rds",
        "Azure_Cosmos_Host": "azure_cosmos",
        "DB_Password_Assignment": "db_password",
        "Firebase": "firebase",
        "Firebase_Database_App": "firebase",
    }
    return mapping.get(name)


def detect_db_urls(job: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    apk = str(job.get("apk") or "")
    pkg = str(job.get("package") or "")

    for name, text in _chunks_from_job(job):
        candidates: list[tuple[str, str]] = []
        kind_from_name = _kind_from_finding_name(name)
        if kind_from_name and name in DB_FINDING_NAMES:
            # Prefer extractor over raw finding text when possible.
            matched = False
            for kind, rx in _EXTRACTORS:
                if kind != kind_from_name and not (
                    kind_from_name == "firebase" and kind == "firebase"
                ):
                    continue
                for m in rx.finditer(text):
                    candidates.append((kind, m.group(1)))
                    matched = True
            if not matched:
                candidates.append((kind_from_name, text))
        for kind, rx in _EXTRACTORS:
            for m in rx.finditer(text):
                candidates.append((kind, m.group(1)))

        for kind, raw in candidates:
            value = raw.strip().strip("'\"")
            if not value or len(value) < 8:
                continue
            if _is_placeholder(value):
                continue
            # Normalize key for dedupe
            key = f"{kind}|{value.lower()}"
            if key in seen:
                continue
            seen.add(key)

            has_creds = _has_embedded_credentials(value)
            local = _is_local(value)
            if has_creds and not local:
                severity = "critical"
            elif has_creds and local:
                severity = "high"
            elif kind in ("db_password",):
                severity = "critical"
            elif local:
                severity = "medium"
            elif kind in ("firebase", "supabase", "aws_rds", "azure_cosmos", "elasticsearch"):
                severity = "high"
            else:
                severity = "high"

            redacted = redact_db_secret(value)
            summary = f"DB_URL:{severity}:{kind}:{redacted}"
            found.append({
                "kind": kind,
                "severity": severity,
                "value": value if not has_creds else redacted,  # never keep clear password in export field
                "value_redacted": redacted,
                "has_credentials": has_creds,
                "local": local,
                "summary": summary,
                "apk": apk,
                "package": pkg,
                "finding_name": name or "",
                "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found.sort(key=lambda r: (rank.get(str(r.get("severity")), 9), str(r.get("kind")), str(r.get("summary"))))
    return found


def merge_db_urls(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = f"{row.get('kind')}|{(row.get('value_redacted') or row.get('value') or '').lower()}|{row.get('apk')}"
        prev = best.get(key)
        if prev is None or rank.get(str(row.get("severity")), 9) < rank.get(str(prev.get("severity")), 9):
            best[key] = row
    out = list(best.values())
    out.sort(key=lambda r: (rank.get(str(r.get("severity")), 9), str(r.get("kind")), str(r.get("apk"))))
    return out


def scan_results_dir(results_dir: Path) -> dict[str, Any]:
    skip = {
        "status.json",
        "summary.json",
        "dashboard-config.json",
        "download-status.json",
        "loop-status.json",
        "firebase-access.json",
        "admin-sdk-access.json",
        "db-urls.json",
    }
    rows: list[dict[str, Any]] = []
    if results_dir.is_dir():
        for path in sorted(results_dir.glob("*.json")):
            if path.name in skip:
                continue
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(job, dict):
                continue
            existing = job.get("db_urls") or []
            if existing:
                rows.extend(x for x in existing if isinstance(x, dict))
            else:
                rows.extend(detect_db_urls(job))
    merged = merge_db_urls(rows)
    critical = [r for r in merged if r.get("severity") == "critical"]
    high = [r for r in merged if r.get("severity") == "high"]
    by_kind: dict[str, int] = {}
    for r in merged:
        k = str(r.get("kind") or "unknown")
        by_kind[k] = by_kind.get(k, 0) + 1
    summary = {
        "ok": True,
        "total": len(merged),
        "critical_count": len(critical),
        "high_count": len(high),
        "with_credentials": sum(1 for r in merged if r.get("has_credentials")),
        "by_kind": by_kind,
        "critical": critical,
        "high": high,
        "results": merged,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "message": (
            f"{len(critical)} critical / {len(high)} high DB URL(s); "
            f"{sum(1 for r in merged if r.get('has_credentials'))} with credentials"
            if merged
            else "No database URLs / connection strings found"
        ),
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "db-urls.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan results for database URLs / connection strings")
    parser.add_argument("--results", default="results")
    args = parser.parse_args()
    summary = scan_results_dir(Path(args.results))
    print(json.dumps({
        "ok": summary["ok"],
        "total": summary["total"],
        "critical_count": summary["critical_count"],
        "high_count": summary["high_count"],
        "with_credentials": summary["with_credentials"],
        "by_kind": summary["by_kind"],
        "message": summary["message"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
