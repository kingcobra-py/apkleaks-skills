#!/usr/bin/env python3
"""Normalize scan findings into priority secrets + other APIs.

Priority box: AWS Key:Secret pairs, SendGrid (SG....), Stripe sk_live_...
Other box: any other credential-like API/token values.
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
SENDGRID_NAMES = {
    "SendGrid_API_Key",
}
STRIPE_LIVE_NAMES = {
    "Stripe_API_Key",
    "Picatic_API_Key",
    "Stripe_Restricted_API_Key",
}

# Finding categories that are almost always noise for "raw secret" export.
NOISE_FINDING_NAMES = {
    "Amazon_AWS_S3_Bucket",
    "Authorization_Basic",
    "JSON_Web_Token",
    "Artifactory_Password",
    "Artifactory_API_Token",
    "LinkFinder",
    "URL",
    "Email",
    "IP_Address",
    "IPv4",
    "IPv6",
}

_AKIA_RE = re.compile(r"(?:^|[^A-Z0-9])((?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16})")
_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/=])")
_SENDGRID_RE = re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
_SK_LIVE_RE = re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")
_RK_LIVE_RE = re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b")

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


def _extract_sendgrid(raw: str) -> str | None:
    m = _SENDGRID_RE.search(raw)
    return m.group(0) if m else None


def _extract_sk_live(raw: str) -> str | None:
    m = _SK_LIVE_RE.search(raw) or _RK_LIVE_RE.search(raw)
    return m.group(0) if m else None


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
    if re.match(r"(?i)^basic(\s|$|=)", v) and "ey" not in v and len(v) < 40:
        return True
    if v.count(".") >= 2 and not _JWT_RE.match(v):
        if "Gradle" in v or "version" in v.lower():
            return True
    return False


def looks_like_secret(name: str, value: str) -> bool:
    """Keep only high-signal credential-like values for non-AWS categories."""
    if name in NOISE_FINDING_NAMES:
        return False
    if is_noise_value(value):
        return False
    if name == "JSON_Web_Token":
        return bool(_JWT_RE.match(value)) and value.startswith("eyJ")
    if name == "Authorization_Bearer":
        return bool(re.search(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", value)) and len(value) >= 20
    if len(value) < 12:
        return False
    if " " in value and not re.search(r"[A-Za-z0-9_\-]{16,}", value):
        return False
    return True


def _classify_priority_value(name: str, match: str) -> tuple[str | None, str | None]:
    """Return (bucket, cleaned_value) where bucket is 'priority' or 'other'."""
    if name in SENDGRID_NAMES or _SENDGRID_RE.search(match):
        sg = _extract_sendgrid(match) or (match if match.startswith("SG.") else None)
        if sg and not is_noise_value(sg):
            return "priority", sg
    if name in STRIPE_LIVE_NAMES or _SK_LIVE_RE.search(match) or _RK_LIVE_RE.search(match):
        sk = _extract_sk_live(match) or (
            match if match.startswith("sk_live_") or match.startswith("rk_live_") else None
        )
        if sk and not is_noise_value(sk):
            return "priority", sk
    return None, None


def normalize_job_findings(job: dict[str, Any]) -> dict[str, Any]:
    """Return priority/other secret lists from a batch job or CLI data blob."""
    findings = job.get("findings") or job.get("results") or []
    aws_keys: list[str] = []
    aws_secrets: list[str] = []
    priority: list[str] = []
    other: list[str] = []

    def _add(bucket: list[str], value: str) -> None:
        if value and value not in bucket:
            bucket.append(value)

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        name = finding.get("name") or ""
        if name in NOISE_FINDING_NAMES and name not in AWS_KEY_NAMES and name not in AWS_SECRET_NAMES:
            continue
        for match in _extract_matches(finding):
            if name in AWS_KEY_NAMES:
                key = _clean_aws_key(match)
                if key:
                    _add(aws_keys, key)
                continue
            if name in AWS_SECRET_NAMES:
                secret = _clean_aws_secret(match)
                if secret:
                    _add(aws_secrets, secret)
                continue

            bucket, cleaned = _classify_priority_value(name, match)
            if bucket == "priority" and cleaned:
                _add(priority, cleaned)
                continue

            if not looks_like_secret(name, match):
                continue
            # Value-level priority catch (even if category name differs)
            bucket2, cleaned2 = _classify_priority_value("", match)
            if bucket2 == "priority" and cleaned2:
                _add(priority, cleaned2)
                continue
            if not is_noise_value(match):
                _add(other, match)

    aws_pairs: list[str] = []
    if aws_keys and aws_secrets:
        for key in aws_keys:
            for secret in aws_secrets:
                pair = f"{key}:{secret}"
                if pair not in aws_pairs:
                    aws_pairs.append(pair)
                    _add(priority, pair)
    elif aws_keys:
        for key in aws_keys:
            _add(other, key)
    elif aws_secrets:
        for secret in aws_secrets:
            _add(other, secret)

    priority = [x for x in priority if not is_noise_value(x) or ":" in x]
    other = [x for x in other if not is_noise_value(x) and x not in priority]
    lines = list(priority) + list(other)
    return {
        "raw_lines": lines,
        "priority_lines": priority,
        "other_lines": other,
        "aws_pairs": aws_pairs,
        "sendgrid": [x for x in priority if x.startswith("SG.")],
        "sk_live": [x for x in priority if x.startswith("sk_live_") or x.startswith("rk_live_")],
        "raw_other": other,
        "finding_count": len(lines),
        "has_aws": bool(aws_pairs),
    }


def _is_priority_line(line: str) -> bool:
    if not line:
        return False
    if line.startswith("SG.") or line.startswith("sk_live_") or line.startswith("rk_live_"):
        return True
    if ":" in line and _AKIA_RE.search(line):
        return True
    return False


def _split_precomputed_lines(lines: list[str], pairs: list[str]) -> dict[str, Any]:
    priority: list[str] = []
    other: list[str] = []
    for line in list(pairs) + list(lines):
        if not line:
            continue
        if is_noise_value(line) and not _is_priority_line(line):
            continue
        if _is_priority_line(line):
            if line not in priority:
                priority.append(line)
        elif line not in other and line not in priority:
            other.append(line)
    return {
        "priority_lines": priority,
        "other_lines": other,
        "aws_pairs": [x for x in priority if ":" in x and _AKIA_RE.search(x)],
        "raw_lines": priority + other,
        "sendgrid": [x for x in priority if x.startswith("SG.")],
        "sk_live": [x for x in priority if x.startswith("sk_live_") or x.startswith("rk_live_")],
        "raw_other": other,
        "finding_count": len(priority) + len(other),
        "has_aws": any(":" in x and _AKIA_RE.search(x) for x in priority),
    }


def aggregate_results(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    priority: list[str] = []
    other: list[str] = []
    aws_pairs: list[str] = []
    by_apk: list[dict[str, Any]] = []

    for job in jobs:
        if not isinstance(job, dict):
            continue
        if job.get("findings") or job.get("results"):
            norm = normalize_job_findings(job)
        elif job.get("raw_lines") or job.get("aws_pairs") or job.get("priority_lines"):
            lines = job.get("priority_lines") or job.get("raw_lines") or []
            # If both priority/other already present, prefer them
            if job.get("priority_lines") is not None or job.get("other_lines") is not None:
                norm = {
                    "priority_lines": [x for x in (job.get("priority_lines") or []) if x],
                    "other_lines": [x for x in (job.get("other_lines") or []) if x and not is_noise_value(x)],
                    "aws_pairs": job.get("aws_pairs") or [],
                    "raw_lines": [],
                    "sendgrid": [],
                    "sk_live": [],
                    "raw_other": [],
                    "finding_count": 0,
                    "has_aws": False,
                }
                norm["raw_lines"] = list(norm["priority_lines"]) + list(norm["other_lines"])
                norm["finding_count"] = len(norm["raw_lines"])
                norm["sendgrid"] = [x for x in norm["priority_lines"] if x.startswith("SG.")]
                norm["sk_live"] = [
                    x for x in norm["priority_lines"] if x.startswith("sk_live_") or x.startswith("rk_live_")
                ]
                norm["has_aws"] = bool(norm["aws_pairs"])
            else:
                norm = _split_precomputed_lines(
                    [x for x in (job.get("raw_lines") or []) if x],
                    [x for x in (job.get("aws_pairs") or []) if x],
                )
        else:
            continue

        p_lines = norm.get("priority_lines") or []
        o_lines = norm.get("other_lines") or []
        pairs = norm.get("aws_pairs") or []
        entry = {
            "apk": job.get("apk"),
            "ok": job.get("ok"),
            "priority_lines": p_lines,
            "other_lines": o_lines,
            "raw_lines": list(p_lines) + list(o_lines),
            "aws_pairs": pairs,
            "finding_count": len(p_lines) + len(o_lines),
        }
        if entry["finding_count"]:
            by_apk.append(entry)
        for line in p_lines:
            if line not in priority:
                priority.append(line)
        for line in o_lines:
            if line not in other and line not in priority:
                other.append(line)
        for pair in pairs:
            if pair not in aws_pairs:
                aws_pairs.append(pair)

    all_lines = list(priority) + list(other)
    return {
        "ok": True,
        "total": len(all_lines),
        "priority_total": len(priority),
        "other_total": len(other),
        "priority_lines": priority,
        "other_lines": other,
        "aws_pairs": aws_pairs,
        "sendgrid": [x for x in priority if x.startswith("SG.")],
        "sk_live": [x for x in priority if x.startswith("sk_live_") or x.startswith("rk_live_")],
        "lines": all_lines,
        "by_apk": by_apk,
        "text": "\n".join(all_lines) + ("\n" if all_lines else ""),
        "priority_text": "\n".join(priority) + ("\n" if priority else ""),
        "other_text": "\n".join(other) + ("\n" if other else ""),
    }
