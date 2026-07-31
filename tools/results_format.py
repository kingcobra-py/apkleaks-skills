#!/usr/bin/env python3
"""Normalize scan findings into priority secrets + other APIs.

Priority box: AWS Key:Secret pairs, SendGrid (SG....), Stripe sk_live_...
Other box: any other credential-like API/token values.
"""

from __future__ import annotations

import re
from collections import Counter
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
ADMIN_SDK_NAMES = {
    "Google_Cloud_Platform_Service_Account",
    "RSA_Private_Key",
    "SSH_DSA_Private_Key",
    "SSH_EC_Private_Key",
    "Private_Key_Generic",
    "Firebase_Admin_SDK_Email",
    "Google_Service_Account_Email",
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

_AKIA_RE = re.compile(
    r"(?:^|[^A-Z0-9])((?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16})(?![A-Z0-9])"
)
_AKIA_FULL_RE = re.compile(r"^(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16}$")
_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/=])")
_SENDGRID_RE = re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
_SK_LIVE_RE = re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")
_RK_LIVE_RE = re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b")
_AWS_EXAMPLE_MARKERS = ("EXAMPLE", "TESTKEY", "FAKESECRET", "DUMMY", "CHANGEME")

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


def is_plausible_aws_access_key(key: str) -> bool:
    """Reject English/placeholder strings that only look like AKIA… tokens."""
    if not key or not _AKIA_FULL_RE.fullmatch(key):
        return False
    upper = key.upper()
    if any(marker in upper for marker in _AWS_EXAMPLE_MARKERS):
        return False
    # Real AWS access key IDs always include digits; letter-only hits are usually words.
    if not re.search(r"\d", key):
        return False
    # Too little variety (AKIA0000… / AKIAAAAA…)
    if len(set(key[4:])) < 6:
        return False
    return True


def _clean_aws_key(raw: str) -> str | None:
    m2 = _AKIA_RE.search(raw)
    if m2:
        key = m2.group(1).strip()
        return key if is_plausible_aws_access_key(key) else None
    token = re.sub(r"[^A-Za-z0-9]", "", raw)
    if _AKIA_FULL_RE.fullmatch(token) and is_plausible_aws_access_key(token):
        return token
    return None


def _clean_aws_secret(raw: str) -> str | None:
    m = re.search(
        r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?",
        raw,
    )
    secret: str | None = None
    if m:
        secret = m.group(1)
    else:
        m2 = _SECRET_RE.search(raw)
        if m2:
            secret = m2.group(1)
        else:
            token = raw.strip().strip("'\"").strip()
            if re.fullmatch(r"[A-Za-z0-9+/]{40}", token):
                secret = token
    if not secret:
        return None
    upper = secret.upper()
    if any(marker in upper for marker in _AWS_EXAMPLE_MARKERS):
        return None
    return secret


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
    low = v.lower()
    # Decompiler / Android framework false positives for Generic_Password etc.
    junk_snippets = (
        "accessibilitynodeinfo",
        "ispassword()",
        "toindentedstring",
        "sb.append(",
        "passwordcertainty",
        "-----begin ",
        "changeit",
    )
    if any(s in low for s in junk_snippets):
        return True
    # Structured high-signal formats — skip entropy heuristics.
    if _SENDGRID_RE.fullmatch(v) or _SK_LIVE_RE.fullmatch(v) or _RK_LIVE_RE.fullmatch(v):
        return False
    stripped = v.strip()
    if _AKIA_FULL_RE.fullmatch(stripped):
        return not is_plausible_aws_access_key(stripped)
    m_akia = _AKIA_RE.search(v)
    if m_akia:
        return not is_plausible_aws_access_key(m_akia.group(1))
    if _is_low_entropy_token(v):
        return True
    return False


def _is_low_entropy_token(value: str) -> bool:
    """Reject repetitive / keyboard-mash tokens that loose regexes love."""
    v = value.strip().strip("'\"")
    # Strip common prefixes for entropy check
    body = v
    stripped_prefix = ""
    for prefix in ("bk", "oy2", "SG.", "AC", "SK", "AKIA"):
        if body.startswith(prefix):
            stripped_prefix = prefix
            body = body[len(prefix) :]
            break
    if len(body) < 12:
        return False
    # Too many identical characters
    counts = Counter(body.lower())
    most = counts.most_common(1)[0][1]
    if most / max(1, len(body)) >= 0.35:
        return True
    # Mostly sequential runs (abcde / 12345) or alternating pairs
    asc = sum(1 for i in range(len(body) - 1) if ord(body[i + 1]) - ord(body[i]) == 1)
    if asc / max(1, len(body) - 1) >= 0.45:
        return True
    # Very few unique chars overall
    if len(counts) <= max(4, len(body) // 10):
        return True
    # Prefixed tokens (bk… / oy2…) that are mostly lowercase syllables
    if stripped_prefix in {"bk", "oy2"} and re.fullmatch(r"[a-z0-9_-]+", body) and body.islower():
        digit_ratio = sum(ch.isdigit() for ch in body) / max(1, len(body))
        if digit_ratio < 0.12:
            return True
    # Obvious source/identifier noise
    noise_bits = (
        "file_text",
        "sort_by",
        "alphabet",
        "attribute",
        "bls12_",
        "eip-",
        "jwk_",
        "Qab",
        "lsbls",
        "remye",
        "dreye",
        "lenye",
        "letye",
    )
    low = v.lower()
    if any(b.lower() in low for b in noise_bits):
        return True
    return False


def looks_like_secret(name: str, value: str) -> bool:
    """Keep only high-signal credential-like values for non-AWS categories."""
    if name in NOISE_FINDING_NAMES:
        return False
    if is_noise_value(value):
        return False
    if name == "Generic_Password":
        # Require a short assignment-like secret, not source dumps.
        if "\n" in value or len(value) > 80:
            return False
        if not re.search(r"(?i)password\s*[:=]\s*\S+", value):
            return False
        # Reject values that are clearly code fragments.
        if any(tok in value for tok in ("(", ")", ";", "append", "String")):
            return False
    if name == "Buildkite_API_Token":
        # Real tokens aren't pure lowercase runs / repeated Qab fragments.
        body = value[2:] if value.startswith("bk") else value
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", body):
            return False
        if body.islower() or body.isupper():
            return False
        if not re.search(r"[0-9]", body):
            return False
        if not re.search(r"[A-Z]", body) or not re.search(r"[a-z]", body):
            return False
    if name == "Twilio_Account_SID":
        if not re.fullmatch(r"AC[a-fA-F0-9]{32}", value):
            return False
        # Reject all-same-nibble junk like AC0000...
        hexpart = value[2:]
        if len(set(hexpart.lower())) < 6:
            return False
    if name == "NuGet_API_Key":
        if not re.fullmatch(r"oy2[a-zA-Z0-9_-]{43}", value):
            return False
        body = value[3:]
        if body.islower() and not re.search(r"[0-9]", body):
            return False
        # Reject dictionary-syllable mash (almost no uppercase / few digits).
        if body.islower() and sum(ch.isdigit() for ch in body) < 4:
            return False
        if not re.search(r"[A-Z]", body):
            # Allow digit-heavy lowercase keys only.
            if sum(ch.isdigit() for ch in body) < 8:
                return False
    if name == "JSON_Web_Token":
        return bool(_JWT_RE.match(value)) and value.startswith("eyJ")
    if name == "Authorization_Bearer":
        return bool(re.search(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", value)) and len(value) >= 20
    if name in {"RSA_Private_Key", "SSH_DSA_Private_Key", "SSH_EC_Private_Key", "Private_Key_Generic"}:
        # PEM headers alone are not useful exports.
        return False
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


def format_other_line(name: str, value: str) -> str:
    """Label other-API hits so the dashboard shows what pattern matched."""
    label = (name or "Unknown").strip() or "Unknown"
    return f"{label}: {value}"


def _other_value_part(line: str) -> str:
    """Extract raw value from `Name: value` (or return line as-is)."""
    if ": " in line:
        return line.split(": ", 1)[1]
    return line


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
                label = name or "Unknown_API"
                _add(other, format_other_line(label, match))

    aws_pairs: list[str] = []
    if aws_keys and aws_secrets:
        for key in aws_keys:
            for secret in aws_secrets:
                pair = f"{key}:{secret}"
                if pair not in aws_pairs:
                    aws_pairs.append(pair)
                    _add(priority, pair)
    else:
        # Keep unpaired AWS material in Priority so it does not vanish into Other.
        for key in aws_keys:
            _add(priority, key)
        for secret in aws_secrets:
            _add(priority, secret)

    # Correlated Admin SDK / GCP service-account leaks → Priority.
    try:
        from admin_sdk_detect import detect_admin_sdk  # local tools import
    except ImportError:  # pragma: no cover
        detect_admin_sdk = None  # type: ignore[assignment]
    admin_sdk: list[dict[str, Any]] = []
    if detect_admin_sdk is not None:
        admin_sdk = detect_admin_sdk({
            "findings": findings,
            "apk": job.get("apk") or "",
            "package": job.get("package") or "",
            "raw_lines": [],
            "priority_lines": [],
            "other_lines": [],
        })
        for hit in admin_sdk:
            if hit.get("severity") in ("critical", "high") and hit.get("summary"):
                _add(priority, str(hit["summary"]))

    priority = [x for x in priority if keep_priority_line(x)]
    # Drop other lines whose raw value is noise, or that duplicate a priority value
    priority_values = set(priority)
    cleaned_other: list[str] = []
    for line in other:
        raw = _other_value_part(line)
        if is_noise_value(raw):
            continue
        if raw in priority_values or line in priority_values:
            continue
        # Avoid duplicating raw SA/private-key fragments already summarized.
        if line.startswith("ADMIN_SDK:"):
            continue
        label = line.split(":", 1)[0].strip() if ":" in line else ""
        if label in ADMIN_SDK_NAMES:
            continue
        if line not in cleaned_other:
            cleaned_other.append(line)
    other = cleaned_other
    lines = list(priority) + list(other)
    return {
        "raw_lines": lines,
        "priority_lines": priority,
        "other_lines": other,
        "aws_pairs": aws_pairs,
        "admin_sdk": admin_sdk,
        "sendgrid": [x for x in priority if x.startswith("SG.")],
        "sk_live": [x for x in priority if x.startswith("sk_live_") or x.startswith("rk_live_")],
        "raw_other": other,
        "finding_count": len(lines),
        "has_aws": bool(aws_pairs),
        "has_admin_sdk": any(h.get("severity") in ("critical", "high") for h in admin_sdk),
    }


def _is_priority_line(line: str) -> bool:
    if not line:
        return False
    if line.startswith("ADMIN_SDK:"):
        return True
    if line.startswith("SG.") or line.startswith("sk_live_") or line.startswith("rk_live_"):
        return True
    if ":" in line and _AKIA_RE.search(line):
        key = line.split(":", 1)[0].strip()
        return is_plausible_aws_access_key(key)
    if _AKIA_FULL_RE.fullmatch(line.strip()):
        return is_plausible_aws_access_key(line.strip())
    return False


def keep_priority_line(line: str) -> bool:
    """Drop placeholder / letter-only AWS leftovers from Priority."""
    if not line:
        return False
    if line.startswith("ADMIN_SDK:"):
        return True
    if line.startswith("SG.") or line.startswith("sk_live_") or line.startswith("rk_live_"):
        return not is_noise_value(line)
    if ":" in line and _AKIA_RE.search(line.split(":", 1)[0]):
        key, secret = line.split(":", 1)
        return is_plausible_aws_access_key(key.strip()) and bool(secret.strip()) and not any(
            m in secret.upper() for m in _AWS_EXAMPLE_MARKERS
        )
    if _AKIA_FULL_RE.fullmatch(line.strip()):
        return is_plausible_aws_access_key(line.strip())
    if re.fullmatch(r"[A-Za-z0-9+/]{40}", line.strip()):
        return not any(m in line.upper() for m in _AWS_EXAMPLE_MARKERS)
    return True


def _split_precomputed_lines(lines: list[str], pairs: list[str]) -> dict[str, Any]:
    priority: list[str] = []
    other: list[str] = []
    for line in list(pairs) + list(lines):
        if not line:
            continue
        raw = _other_value_part(line)
        # Priority detection on unlabeled or labeled lines
        if _is_priority_line(line) or _is_priority_line(raw):
            target = raw if _is_priority_line(raw) and not _is_priority_line(line) else line
            # Prefer unlabeled priority value for AWS/SG/sk_live boxes
            if _is_priority_line(raw):
                target = raw
            if not keep_priority_line(target):
                continue
            if is_noise_value(raw) and not _is_priority_line(raw):
                continue
            if target not in priority:
                priority.append(target)
            continue
        if is_noise_value(raw):
            continue
        # Keep/upgrade to Name: value when possible
        if line not in other and raw not in {_other_value_part(x) for x in other}:
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
        elif (
            job.get("raw_lines")
            or job.get("aws_pairs")
            or job.get("priority_lines") is not None
            or job.get("other_lines") is not None
        ):
            # If both priority/other already present, prefer them
            if job.get("priority_lines") is not None or job.get("other_lines") is not None:
                cleaned_other = []
                for x in job.get("other_lines") or []:
                    if not x:
                        continue
                    raw = _other_value_part(x)
                    name = x.split(": ", 1)[0] if ": " in x else ""
                    if is_noise_value(raw):
                        continue
                    if name and not looks_like_secret(name, raw):
                        continue
                    cleaned_other.append(x)
                norm = {
                    "priority_lines": [
                        x for x in (job.get("priority_lines") or []) if x and keep_priority_line(x)
                    ],
                    "other_lines": cleaned_other,
                    "aws_pairs": [
                        x
                        for x in (job.get("aws_pairs") or [])
                        if x and keep_priority_line(x)
                    ],
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
        # Jobs are expected newest-first; append so Other APIs stay newest→oldest.
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
