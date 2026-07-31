#!/usr/bin/env python3
"""Detect Google/Firebase Admin SDK / service-account credential leaks."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any

# Service-account / Admin SDK markers.
_SERVICE_ACCOUNT_TYPE_RE = re.compile(
    r'"type"\s*:\s*"service_account"',
    re.IGNORECASE,
)
_PRIVATE_KEY_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
)
_PRIVATE_KEY_JSON_RE = re.compile(
    r'"private_key"\s*:\s*"-----BEGIN[^"]*PRIVATE KEY-----',
    re.IGNORECASE,
)
_CLIENT_EMAIL_RE = re.compile(
    r"([a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)",
    re.IGNORECASE,
)
_FIREBASE_ADMIN_EMAIL_RE = re.compile(
    r"(firebase-adminsdk-[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com)",
    re.IGNORECASE,
)
_PROJECT_ID_RE = re.compile(
    r'"project_id"\s*:\s*"([a-z0-9-]+)"',
    re.IGNORECASE,
)
_PRIVATE_KEY_ID_RE = re.compile(
    r'"private_key_id"\s*:\s*"([a-fA-F0-9]{8,})"',
    re.IGNORECASE,
)

SERVICE_ACCOUNT_FINDING_NAMES = {
    "Google_Cloud_Platform_Service_Account",
}
PRIVATE_KEY_FINDING_NAMES = {
    "RSA_Private_Key",
    "SSH_DSA_Private_Key",
    "SSH_EC_Private_Key",
    "Private_Key_Generic",
    "PGP_private_key_block",
}


def _chunks_from_job(job: dict[str, Any]) -> list[str]:
    chunks: list[str] = []
    for finding in job.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        name = str(finding.get("name") or "")
        if name:
            chunks.append(name)
        for m in finding.get("matches") or []:
            if isinstance(m, str) and m.strip():
                chunks.append(m)
            elif isinstance(m, dict):
                chunks.append(json.dumps(m))
    for key in ("raw_lines", "priority_lines", "other_lines"):
        val = job.get(key)
        if isinstance(val, list):
            chunks.extend(str(x) for x in val if x)
    return chunks


def _finding_names(job: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for finding in job.get("findings") or []:
        if isinstance(finding, dict) and finding.get("name"):
            names.add(str(finding["name"]))
    return names


def detect_admin_sdk(job: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Admin SDK / service-account hits for one APK job."""
    chunks = _chunks_from_job(job)
    blob = "\n".join(chunks)
    names = _finding_names(job)

    has_sa_type = bool(_SERVICE_ACCOUNT_TYPE_RE.search(blob)) or bool(
        names & SERVICE_ACCOUNT_FINDING_NAMES
    )
    has_pem = bool(_PRIVATE_KEY_PEM_RE.search(blob)) or bool(_PRIVATE_KEY_JSON_RE.search(blob)) or bool(
        names & PRIVATE_KEY_FINDING_NAMES
    )
    emails = sorted({m.group(1).lower() for m in _CLIENT_EMAIL_RE.finditer(blob)})
    admin_emails = sorted({m.group(1).lower() for m in _FIREBASE_ADMIN_EMAIL_RE.finditer(blob)})
    projects = sorted({m.group(1) for m in _PROJECT_ID_RE.finditer(blob)})
    key_ids = sorted({m.group(1) for m in _PRIVATE_KEY_ID_RE.finditer(blob)})

    if not (has_sa_type or has_pem or emails or admin_emails):
        return []

    # Confidence:
    # - critical: private key + (service_account type OR gsa email / firebase-adminsdk)
    # - high: private key alone, or firebase-adminsdk email without key (still suspicious)
    # - medium: service_account type string alone
    if has_pem and (has_sa_type or emails or admin_emails):
        severity = "critical"
        kind = "admin_sdk_service_account"
        detail = "Service account JSON markers + private key PEM (likely Admin SDK / GCP SA leak)"
    elif has_pem:
        severity = "high"
        kind = "private_key"
        detail = "Private key PEM found (confirm if paired with service account JSON)"
    elif admin_emails:
        severity = "high"
        kind = "firebase_adminsdk_email"
        detail = "firebase-adminsdk service account email found (hunt for private_key)"
    elif has_sa_type and emails:
        severity = "high"
        kind = "service_account_partial"
        detail = "service_account type + client_email (private_key may be nearby)"
    elif has_sa_type:
        severity = "medium"
        kind = "service_account_type"
        detail = 'Only "type": "service_account" marker — verify full JSON / private_key'
    else:
        severity = "medium"
        kind = "service_account_email"
        detail = "GCP service account email found without private key in same scan"

    # Redacted summary line for Priority box — never dump full PEM.
    email_show = (admin_emails or emails or ["unknown-sa"])[0]
    project_show = projects[0] if projects else ""
    summary = f"ADMIN_SDK:{severity}:{email_show}"
    if project_show:
        summary += f":project={project_show}"
    if key_ids:
        summary += f":key_id={key_ids[0][:12]}"

    hit = {
        "kind": kind,
        "severity": severity,
        "summary": summary,
        "detail": detail,
        "has_private_key": has_pem,
        "has_service_account_type": has_sa_type,
        "client_emails": emails[:5],
        "firebase_adminsdk_emails": admin_emails[:5],
        "project_ids": projects[:5],
        "private_key_ids": [k[:16] for k in key_ids[:5]],
        "apk": job.get("apk") or "",
        "package": job.get("package") or "",
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return [hit]


def merge_admin_sdk(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = (
            str(row.get("apk") or ""),
            str(row.get("summary") or row.get("kind") or ""),
        )
        prev = best.get(f"{key[0]}|{key[1]}")
        if prev is None:
            best[f"{key[0]}|{key[1]}"] = row
            continue
        if rank.get(str(row.get("severity")), 9) < rank.get(str(prev.get("severity")), 9):
            best[f"{key[0]}|{key[1]}"] = row
    out = list(best.values())
    out.sort(
        key=lambda r: (
            rank.get(str(r.get("severity")), 9),
            str(r.get("apk") or ""),
            str(r.get("summary") or ""),
        )
    )
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
            # Prefer already-computed field; else detect now.
            existing = job.get("admin_sdk") or []
            if existing:
                rows.extend(x for x in existing if isinstance(x, dict))
            else:
                rows.extend(detect_admin_sdk(job))
    merged = merge_admin_sdk(rows)
    critical = [r for r in merged if r.get("severity") == "critical"]
    high = [r for r in merged if r.get("severity") == "high"]
    summary = {
        "ok": True,
        "total": len(merged),
        "critical_count": len(critical),
        "high_count": len(high),
        "critical": critical,
        "high": high,
        "results": merged,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "message": (
            f"{len(critical)} critical / {len(high)} high Admin SDK-related hit(s)"
            if merged
            else "No Admin SDK / service-account leaks found"
        ),
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "admin-sdk-access.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan results for Admin SDK / service-account leaks")
    parser.add_argument("--results", default="results")
    args = parser.parse_args()
    summary = scan_results_dir(Path(args.results))
    print(json.dumps({
        "ok": summary["ok"],
        "total": summary["total"],
        "critical_count": summary["critical_count"],
        "high_count": summary["high_count"],
        "message": summary["message"],
        "summaries": [r.get("summary") for r in summary.get("results") or []],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
