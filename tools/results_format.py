#!/usr/bin/env python3
"""Normalize scan findings into raw secret lines + AWS Key:Secret pairs."""

from __future__ import annotations

import re
from typing import Any

AWS_KEY_NAMES = {
    "Amazon_AWS_Access_Key_ID",
    "AWS_API_Key",
}
AWS_SECRET_NAMES = {
    "AWS_Secret_Access_Key",
}

# AKIA... style access key id
_AKIA_RE = re.compile(r"(?:^|[^A-Z0-9])((?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{12,})")
# 40-char AWS secret
_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/=]{40})(?![A-Za-z0-9+/=])")


def _extract_matches(finding: dict[str, Any]) -> list[str]:
    matches = finding.get("matches") or []
    if isinstance(matches, str):
        return [matches]
    out: list[str] = []
    for m in matches:
        if isinstance(m, str) and m.strip():
            out.append(m.strip())
        elif isinstance(m, dict):
            for key in ("match", "value", "secret", "text"):
                val = m.get(key)
                if isinstance(val, str) and val.strip():
                    out.append(val.strip())
                    break
    return out


def _clean_aws_key(raw: str) -> str | None:
    m = _AKIA_RE.search(raw.upper() if "AKIA" in raw.upper() else raw)
    if m:
        # Preserve original casing from match group on original text
        m2 = _AKIA_RE.search(raw)
        return (m2.group(1) if m2 else m.group(1)).strip()
    # Sometimes the match is already just the key
    token = re.sub(r"[^A-Za-z0-9]", "", raw)
    if re.fullmatch(r"(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{12,}", token):
        return token
    return None


def _clean_aws_secret(raw: str) -> str | None:
    # Prefer capture group from assignment-style matches
    m = re.search(
        r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{40})['\"]?",
        raw,
    )
    if m:
        return m.group(1)
    m2 = _SECRET_RE.search(raw)
    if m2:
        return m2.group(1)
    token = raw.strip().strip("'\"").strip()
    if re.fullmatch(r"[A-Za-z0-9+/=]{40}", token):
        return token
    return None


def normalize_job_findings(job: dict[str, Any]) -> dict[str, Any]:
    """Return raw_lines, aws_pairs, and count from a batch job or CLI data blob."""
    findings = job.get("findings") or job.get("results") or []
    aws_keys: list[str] = []
    aws_secrets: list[str] = []
    raw_other: list[str] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        name = finding.get("name") or ""
        for match in _extract_matches(finding):
            if name in AWS_KEY_NAMES:
                key = _clean_aws_key(match)
                if key and key not in aws_keys:
                    aws_keys.append(key)
                continue
            if name in AWS_SECRET_NAMES:
                secret = _clean_aws_secret(match)
                if secret and secret not in aws_secrets:
                    aws_secrets.append(secret)
                continue
            # Everything else: raw match value only
            if match not in raw_other:
                raw_other.append(match)

    aws_pairs: list[str] = []
    if aws_keys and aws_secrets:
        for key in aws_keys:
            for secret in aws_secrets:
                pair = f"{key}:{secret}"
                if pair not in aws_pairs:
                    aws_pairs.append(pair)
    elif aws_keys:
        # Key without secret — still surface raw key
        for key in aws_keys:
            if key not in raw_other:
                raw_other.append(key)
    elif aws_secrets:
        for secret in aws_secrets:
            if secret not in raw_other:
                raw_other.append(secret)

    lines = list(aws_pairs) + list(raw_other)
    return {
        "raw_lines": lines,
        "aws_pairs": aws_pairs,
        "raw_other": raw_other,
        "finding_count": len(lines),
        "has_aws": bool(aws_pairs),
    }


def aggregate_results(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    all_lines: list[str] = []
    aws_pairs: list[str] = []
    by_apk: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        norm = normalize_job_findings(job)
        # Prefer precomputed raw_lines if present and non-empty
        lines = job.get("raw_lines") or norm["raw_lines"]
        pairs = job.get("aws_pairs") or norm["aws_pairs"]
        entry = {
            "apk": job.get("apk"),
            "ok": job.get("ok"),
            "raw_lines": lines,
            "aws_pairs": pairs,
            "finding_count": len(lines),
        }
        if lines:
            by_apk.append(entry)
        for line in lines:
            if line not in all_lines:
                all_lines.append(line)
        for pair in pairs:
            if pair not in aws_pairs:
                aws_pairs.append(pair)
    return {
        "ok": True,
        "total": len(all_lines),
        "aws_pairs": aws_pairs,
        "lines": all_lines,
        "by_apk": by_apk,
        "text": "\n".join(all_lines) + ("\n" if all_lines else ""),
    }
