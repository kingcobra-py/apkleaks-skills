#!/usr/bin/env python3
"""Normalize scan findings into raw secret lines + AWS Key:Secret pairs.

Filters out common APKLeaks false positives (S3 hostnames, \"basic ...\" text,
Gradle version strings, Artifactory noise, fake JWTs).
"""

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

# Finding categories that are almost always noise for "raw secret" export.
NOISE_FINDING_NAMES = {
    "Amazon_AWS_S3_Bucket",  # public bucket hostnames, not credentials
    "Authorization_Basic",  # matches English word "basic ..."
    "JSON_Web_Token",  # matches random dotted strings / gradle props
    "Artifactory_Password",  # AP + alnum false positives
    "Artifactory_API_Token",
    "LinkFinder",
    "URL",
    "Email",
    "IP_Address",
    "IPv4",
    "IPv6",
}

# AKIA... style access key id
_AKIA_RE = re.compile(r"(?:^|[^A-Z0-9])((?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16})")
# 40-char AWS secret
_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/=])")

_S3_HOST_RE = re.compile(
    r"(?i)(?:^|[\s\"'])(?:[a-z0-9.-]+\.)?s3[.-][a-z0-9.-]*amazonaws\.com|"
    r"(?:[a-z0-9.-]+\.)?s3-website[-.][a-z0-9.-]+|"
    r"amzn\.mws\."
)
_GRADLE_PROP_RE = re.compile(r"(?i)^androidGradlePluginVersion\s*=")
_BASIC_WORD_RE = re.compile(r"(?i)^basic\s+\S+")
_VERSION_RE = re.compile(r"(?i)^v?\d+\.\d+(\.\d+)?(-[a-z0-9.]+)?$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


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
    m2 = _AKIA_RE.search(raw)
    if m2:
        return m2.group(1).strip()
    token = re.sub(r"[^A-Za-z0-9]", "", raw)
    if re.fullmatch(r"(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16}", token):
        return token
    return None


def _clean_aws_secret(raw: str) -> str | None:
    m = re.search(
        r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?",
        raw,
    )
    if m:
        return m.group(1)
    m2 = _SECRET_RE.search(raw)
    if m2:
        return m2.group(1)
    token = raw.strip().strip("'\"").strip()
    if re.fullmatch(r"[A-Za-z0-9+/]{40}", token):
        return token
    return None


def is_noise_value(value: str) -> bool:
    """Return True if a raw match is known false-positive junk."""
    v = value.strip()
    if not v or len(v) < 8:
        return True
    if _GRADLE_PROP_RE.search(v):
        return True
    if _S3_HOST_RE.search(v) or "s3.amazonaws.com" in v.lower() or "s3-website" in v.lower():
        return True
    if _BASIC_WORD_RE.match(v):
        return True
    if _VERSION_RE.match(v):
        return True
    # Lone "basic" phrases / docs fragments
    if re.match(r"(?i)^basic(\s|$|=)", v) and "ey" not in v and len(v) < 40:
        return True
    # Fake / truncated JWT-looking strings without 3 solid segments
    if v.count(".") >= 2 and not _JWT_RE.match(v):
        # gradle props with dots already handled; drop other dotted junk
        if "Gradle" in v or "version" in v.lower():
            return True
    return False


def looks_like_secret(name: str, value: str) -> bool:
    """Keep only high-signal credential-like values for non-AWS categories."""
    if name in NOISE_FINDING_NAMES:
        return False
    if is_noise_value(value):
        return False
    # Real JWT: header.payload.signature
    if name == "JSON_Web_Token":
        return bool(_JWT_RE.match(value)) and value.startswith("eyJ")
    # Bearer tokens should look like tokens, not "bearer basic docs"
    if name == "Authorization_Bearer":
        return bool(re.search(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", value)) and len(value) >= 20
    # Generic: require some entropy / length
    if len(value) < 12:
        return False
    # Drop pure words / sentences
    if " " in value and not re.search(r"[A-Za-z0-9_\-]{16,}", value):
        return False
    return True


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
        if name in NOISE_FINDING_NAMES and name not in AWS_KEY_NAMES and name not in AWS_SECRET_NAMES:
            continue
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
            if not looks_like_secret(name, match):
                continue
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
        for key in aws_keys:
            if key not in raw_other:
                raw_other.append(key)
    elif aws_secrets:
        # Secret alone is still useful, but only if it came from AWS_Secret pattern
        for secret in aws_secrets:
            if secret not in raw_other:
                raw_other.append(secret)

    # Drop any residual noise that slipped into raw_other
    raw_other = [x for x in raw_other if not is_noise_value(x)]
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
        # Always re-normalize from findings so older noisy raw_lines are cleaned
        if job.get("findings") or job.get("results"):
            norm = normalize_job_findings(job)
        elif job.get("raw_lines") or job.get("aws_pairs"):
            # Fallback: filter precomputed lines
            filtered = [x for x in (job.get("raw_lines") or []) if not is_noise_value(x)]
            pairs = [x for x in (job.get("aws_pairs") or []) if ":" in x and not is_noise_value(x)]
            norm = {
                "raw_lines": pairs + [x for x in filtered if x not in pairs],
                "aws_pairs": pairs,
                "raw_other": [x for x in filtered if x not in pairs],
                "finding_count": 0,
                "has_aws": bool(pairs),
            }
            norm["finding_count"] = len(norm["raw_lines"])
        else:
            continue
        lines = norm["raw_lines"]
        pairs = norm["aws_pairs"]
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
