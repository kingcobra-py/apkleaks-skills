#!/usr/bin/env python3
"""APKLeaks AI-CLI — Structured JSON interface for AI agents.

Key AI-friendly features:
  - schema: self-describing tool definition for AI discovery
  - Structured error codes for programmatic handling
  - Severity classification on scan results
  - explain: contextual explanations of findings
  - Search with file-type filtering and context lines
  - MCP server mode (stdio transport) for direct AI integration

Subcommands:
  schema     — Output tool schema definition (AI self-discovery)
  version    — Show version information
  check      — Verify prerequisites and APK file validity
  info       — Extract APK metadata (package, permissions, activities, etc.)
  scan       — Full scan: decompile + regex pattern matching
  patterns   — List all available regex detection patterns
  decompile  — Decompile APK to Java source using jadx
  search     — Search decompiled source with custom regex
  explain    — Explain a finding category (what it matches, why it matters)
  mcp        — Run as MCP server over stdio (for AI tool integration)
"""

import argparse
import json
import os
import sys
import io
import shutil
import tempfile
import subprocess
import re
import logging
import time

# Lazy import — MCP lifecycle (initialize/ping) works without heavy deps.
# Only actual subcommands (scan/info/etc) need APKLeaks and utils.
_APKLeaks = None
_util = None

def _ensure_imports():
    """Import heavy dependencies only when needed (scan, info, decompile, etc).
    MCP lifecycle methods (initialize, ping, tools/list) work without these.
    """
    global _APKLeaks, _util
    if _APKLeaks is not None:
        return
    try:
        from apkleaks.apkleaks import APKLeaks
        from apkleaks import utils as util
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from apkleaks.apkleaks import APKLeaks
        from apkleaks import utils as util
    _APKLeaks = APKLeaks
    _util = util


VERSION = "1.0.0"

SEVERITY_MAP = {
    "Amazon_AWS_Access_Key_ID": "critical", "Amazon_AWS_S3_Bucket": "critical",
    "AWS_API_Key": "critical", "Artifactory_API_Token": "high",
    "Artifactory_Password": "critical", "Authorization_Basic": "critical",
    "Authorization_Bearer": "critical", "Basic_Auth_Credentials": "critical",
    "Cloudinary_Basic_Auth": "high", "DEFCON_CTF_Flag": "info",
    "Discord_BOT_Token": "high", "Facebook_Access_Token": "high",
    "Facebook_ClientID": "medium", "Facebook_OAuth": "high",
    "Facebook_Secret_Key": "critical", "Firebase": "high",
    "Generic_API_Key": "medium", "Generic_Secret": "medium",
    "GitHub": "high", "GitHub_Access_Token": "critical",
    "Google_API_Key": "high", "Google_Cloud_Platform_OAuth": "high",
    "Google_Cloud_Platform_Service_Account": "critical",
    "Google_OAuth_Access_Token": "high", "HackerOne_CTF_Flag": "info",
    "HackTheBox_CTF_Flag": "info", "TryHackMe_CTF_Flag": "info",
    "Heroku_API_Key": "high", "IP_Address": "low",
    "JSON_Web_Token": "high", "LinkFinder": "medium",
    "Mac_Address": "low", "MailChimp_API_Key": "high",
    "Mailgun_API_Key": "high", "Mailto": "low",
    "Password_in_URL": "critical", "PayPal_Braintree_Access_Token": "critical",
    "PGP_private_key_block": "critical", "Picatic_API_Key": "high",
    "RSA_Private_Key": "critical", "Slack_Token": "high",
    "Slack_Webhook": "medium", "Square_Access_Token": "critical",
    "Square_OAuth_Secret": "critical", "SSH_DSA_Private_Key": "critical",
    "SSH_EC_Private_Key": "critical", "Stripe_API_Key": "critical",
    "Stripe_Restricted_API_Key": "critical", "Twilio_API_Key": "high",
    "Twitter_Access_Token": "high", "Twitter_ClientID": "medium",
    "Twitter_OAuth": "high", "Twitter_Secret_Key": "critical",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

EXPLANATIONS = {
    "Amazon_AWS_Access_Key_ID": "AWS Access Key IDs (AKIA prefix) identify an IAM user. If found with the secret key, an attacker gets full AWS access. Rotate immediately.",
    "Amazon_AWS_S3_Bucket": "S3 bucket URLs may expose stored data. Check for public access. Misconfigured buckets are a common data leak vector.",
    "AWS_API_Key": "AWS API keys provide access to Amazon Web Services. Compromised keys allow attackers to access resources or incur charges.",
    "Authorization_Bearer": "OAuth 2.0 bearer tokens grant the same access as the token holder. Check token expiration and revocation.",
    "Authorization_Basic": "Base64-encoded username:password. Easily decoded. Can authenticate to the associated service.",
    "Basic_Auth_Credentials": "Hardcoded username:password in source code. Not obfuscated, trivially extracted from APK.",
    "Firebase": "Firebase URLs (firebaseio.com) often have weak security rules. Check for unauthenticated read/write access.",
    "Generic_API_Key": "Matches common API key patterns. Could be for any service. Verify by testing against known API endpoints.",
    "Generic_Secret": "Matches common secret/password patterns. Check surrounding code for which service uses this secret.",
    "GitHub_Access_Token": "GitHub tokens (ghp_ prefix) provide API access to repos, orgs. Revoke at github.com/settings/tokens.",
    "Google_API_Key": "Google API keys (AIza prefix) for Maps, YouTube, etc. Unrestricted keys can be abused for some services.",
    "Google_Cloud_Platform_Service_Account": "GCP service account keys provide full project access. Fully compromised if found.",
    "JSON_Web_Token": "JWTs (eyJ prefix) contain encoded claims. If signing key is also found, tokens can be forged.",
    "LinkFinder": "URLs and API endpoints revealing backend infrastructure. Check for admin panels and unauthenticated APIs.",
    "PGP_private_key_block": "PGP private keys decrypt messages and sign as key owner. All encrypted communications compromised.",
    "RSA_Private_Key": "RSA private keys decrypt TLS traffic and impersonate key owner. May be used for cert pinning — extract for Frida MITM.",
    "Stripe_API_Key": "Stripe keys (sk_live_) provide full payment access. Can issue refunds, access customer data. Revoke immediately.",
    "SSH_DSA_Private_Key": "SSH DSA private keys authenticate to servers. Unprotected keys grant immediate server access.",
    "SSH_EC_Private_Key": "SSH EC private keys (Ed25519/ECDSA) authenticate to servers. Leaked key = full credential compromise.",
    "Password_in_URL": "Passwords in URLs (user:pass@host) are logged in server logs and proxy caches. Change immediately.",
}

ERROR_CODES = {
    "FILE_NOT_FOUND": "APK file does not exist at the specified path",
    "INVALID_APK": "File exists but is not a valid Android APK",
    "JADX_NOT_FOUND": "jadx decompiler binary is not available",
    "JADX_FAILED": "jadx decompilation failed",
    "JADX_TIMEOUT": "jadx decompilation exceeded time limit",
    "INVALID_REGEX": "Provided regex pattern is invalid",
    "DIR_NOT_FOUND": "Specified directory does not exist",
    "NO_FINDINGS": "Scan completed but no secrets were found",
    "SCAN_FAILED": "Scanning process encountered an error",
    "MISSING_ARG": "Required argument not provided",
    "PATTERN_FILE_NOT_FOUND": "Custom pattern file not found",
}

FILE_TYPE_EXTENSIONS = {
    "java": (".java",),
    "xml": (".xml",),
    "json": (".json",),
    "smali": (".smali",),
    "properties": (".properties",),
    "yaml": (".yml", ".yaml"),
}


# ─── Helpers ────────────────────────────────────────────────────

def _json_response(ok=True, data=None, error=None, error_code=None, duration_ms=None):
    resp = {"ok": ok, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    if duration_ms is not None:
        resp["duration_ms"] = duration_ms
    if data is not None:
        resp["data"] = data
    if error is not None:
        resp["error"] = error
    if error_code is not None:
        resp["error_code"] = error_code
    return resp


def _write_json(resp):
    print(json.dumps(resp, indent=2, ensure_ascii=False))


def _silence_logs():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})


def _get_severity(category_name):
    return SEVERITY_MAP.get(category_name, "medium")


def _classify_findings(results_list):
    classified = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results_list:
        name = result.get("name", "")
        severity = _get_severity(name)
        matches = result.get("matches", [])
        severity_counts[severity] += len(matches)
        classified.append({
            "name": name, "severity": severity,
            "match_count": len(matches), "matches": matches,
        })
    classified.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 3))
    total = sum(severity_counts.values())
    return {
        "total_findings": total, "severity_counts": severity_counts,
        "has_critical": severity_counts["critical"] > 0, "results": classified,
    }


def _categorize_permissions(permissions):
    categories = {
        "network": [], "storage": [], "location": [],
        "camera_microphone": [], "contacts_phone": [], "system": [], "other": [],
    }
    for p in permissions:
        pl = p.lower()
        if any(k in pl for k in ["internet", "network", "wifi", "bluetooth", "nfc"]):
            categories["network"].append(p)
        elif any(k in pl for k in ["storage", "read_external", "write_external", "media"]):
            categories["storage"].append(p)
        elif any(k in pl for k in ["location", "gps"]):
            categories["location"].append(p)
        elif any(k in pl for k in ["camera", "microphone", "audio", "record"]):
            categories["camera_microphone"].append(p)
        elif any(k in pl for k in ["contact", "phone", "call", "sms"]):
            categories["contacts_phone"].append(p)
        elif any(k in pl for k in ["system", "boot", "install", "overlay", "admin"]):
            categories["system"].append(p)
        else:
            categories["other"].append(p)
    return {k: v for k, v in categories.items() if v}


def _resolve_jadx():
    jadx_path = shutil.which("jadx")
    if not jadx_path:
        main_dir = os.path.dirname(os.path.abspath(__file__))
        jadx_dir = os.path.join(main_dir, "jadx", "bin")
        jadx_name = "jadx.bat" if os.name == "nt" else "jadx"
        jadx_path = os.path.join(jadx_dir, jadx_name)
    return jadx_path


# ─── schema ─────────────────────────────────────────────────────

def cmd_schema(args):
    schema = {
        "name": "apkleaks-ai-cli",
        "version": VERSION,
        "description": "Android APK security scanner — decompiles APKs and scans for leaked secrets",
        "subcommands": [
            {"name": "schema", "description": "Output tool schema definition for AI self-discovery",
             "args": [], "returns": "Tool metadata with all subcommand definitions"},
            {"name": "version", "description": "Show version information",
             "args": [], "returns": "Version and Python version"},
            {"name": "check", "description": "Verify prerequisites and optionally validate an APK",
             "args": [{"name": "file", "flag": "-f", "type": "string", "required": False}],
             "returns": "Prerequisite check results"},
            {"name": "info", "description": "Extract APK metadata without decompiling",
             "args": [{"name": "file", "flag": "-f", "type": "string", "required": True}],
             "returns": "Package, permissions, activities, services, SDK version, permission categories"},
            {"name": "scan", "description": "Full scan: decompile + regex scan with severity classification",
             "args": [{"name": "file", "flag": "-f", "type": "string", "required": True},
                      {"name": "pattern", "flag": "-p", "type": "string", "required": False},
                      {"name": "jadx_args", "flag": "-a", "type": "string", "required": False},
                      {"name": "severity", "flag": "-s", "type": "string", "required": False,
                       "description": "Filter: critical/high/medium/low/info"}],
             "returns": "Classified findings with severity, total counts, has_critical flag",
             "duration": "30-180 seconds"},
            {"name": "patterns", "description": "List regex detection pattern categories",
             "args": [{"name": "verbose", "flag": "-v", "type": "boolean", "required": False}],
             "returns": "Pattern names, severities, types, counts"},
            {"name": "decompile", "description": "Decompile APK to Java source using jadx",
             "args": [{"name": "file", "flag": "-f", "type": "string", "required": True},
                      {"name": "output_dir", "flag": "-o", "type": "string", "required": False},
                      {"name": "jadx_args", "flag": "-a", "type": "string", "required": False}],
             "returns": "Output directory and file count", "duration": "30-120 seconds"},
            {"name": "search", "description": "Search decompiled source with custom regex",
             "args": [{"name": "dir", "flag": "-d", "type": "string", "required": True},
                      {"name": "pattern", "flag": "-p", "type": "string", "required": True},
                      {"name": "limit", "flag": "-l", "type": "number", "required": False},
                      {"name": "type", "flag": "-t", "type": "string", "required": False,
                       "description": "File type: java/xml/json/smali/all"},
                      {"name": "context", "flag": "-c", "type": "number", "required": False,
                       "description": "Context lines around match"}],
             "returns": "Matches with file, line, match text, context lines"},
            {"name": "explain", "description": "Explain what a finding category means",
             "args": [{"name": "category", "flag": "-c", "type": "string", "required": True}],
             "returns": "Category name, severity, description, impact, remediation"},
            {"name": "mcp", "description": "Run as MCP server over stdio",
             "args": [], "returns": "MCP protocol messages on stdio"},
        ],
        "error_codes": ERROR_CODES,
        "response_format": {
            "success": {"ok": True, "data": "...", "timestamp": "ISO 8601", "duration_ms": "int"},
            "error": {"ok": False, "error": "string", "error_code": "string", "timestamp": "ISO 8601"},
        },
    }
    return _json_response(ok=True, data=schema)


# ─── version ────────────────────────────────────────────────────

def cmd_version(args):
    return _json_response(ok=True, data={
        "version": VERSION,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    })


# ─── check ──────────────────────────────────────────────────────

def cmd_check(args):
    checks = {}
    checks["python"] = {
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "ok": sys.version_info >= (3, 8),
    }
    jadx_path = _resolve_jadx()
    checks["jadx"] = {"path": jadx_path, "ok": os.path.isfile(jadx_path) if jadx_path else False}
    try:
        import apkleaks
        checks["apkleaks"] = {"ok": True, "path": os.path.dirname(apkleaks.__file__)}
    except ImportError:
        checks["apkleaks"] = {"ok": False, "path": None}
    try:
        import pyaxmlparser
        checks["pyaxmlparser"] = {"ok": True}
    except ImportError:
        checks["pyaxmlparser"] = {"ok": False}

    if args.file:
        if os.path.isfile(args.file):
            try:
                from pyaxmlparser import APK
                apk = APK(args.file)
                checks["apk"] = {
                    "ok": True, "package": apk.get_package(),
                    "main_activity": apk.get_main_activity(),
                    "permissions": apk.get_permissions(),
                }
            except Exception as e:
                checks["apk"] = {"ok": False, "error": str(e), "error_code": "INVALID_APK"}
        else:
            checks["apk"] = {"ok": False, "error": "File not found", "error_code": "FILE_NOT_FOUND"}
    else:
        checks["apk"] = {"ok": None, "note": "No APK file specified"}

    all_ok = all(
        c.get("ok", False) if c.get("ok") is not None else True
        for c in checks.values()
    )
    return _json_response(ok=all_ok, data=checks)


# ─── info ───────────────────────────────────────────────────────

def cmd_info(args):
    if not os.path.isfile(args.file):
        return _json_response(ok=False, error=f"APK file not found: {args.file}", error_code="FILE_NOT_FOUND")
    start = time.time()
    try:
        from pyaxmlparser import APK as APKParser
        apk = APKParser(args.file)
        data = {
            "file": os.path.basename(args.file),
            "file_size_mb": round(os.path.getsize(args.file) / (1024 * 1024), 2),
            "package": apk.get_package(),
            "main_activity": apk.get_main_activity(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_version_name(),
            "version_code": apk.get_version_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
            "is_valid": apk.is_valid_android(),
            "permission_summary": _categorize_permissions(apk.get_permissions()),
        }
        elapsed = int((time.time() - start) * 1000)
        return _json_response(ok=True, data=data, duration_ms=elapsed)
    except Exception as e:
        return _json_response(ok=False, error=str(e), error_code="INVALID_APK")


# ─── scan ───────────────────────────────────────────────────────

def cmd_scan(args):
    if not os.path.isfile(args.file):
        return _json_response(ok=False, error=f"APK file not found: {args.file}", error_code="FILE_NOT_FOUND")
    _silence_logs()
    start = time.time()

    class FakeArgs:
        pass
    fake = FakeArgs()
    fake.file = args.file
    fake.output = None
    fake.pattern = args.pattern
    fake.args = args.jadx_args
    fake.json = True

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    original_input = getattr(__builtins__, "input", None)
    __builtins__.input = lambda _: "Y"

    runner = None
    try:
        _ensure_imports()
        runner = _APKLeaks(fake)
        runner.integrity()
        runner.decompile()
        runner.scanning()

        raw_results = runner.out_json.copy()
        results_list = raw_results.get("results", [])
        classified = _classify_findings(results_list)

        if args.severity:
            min_sev = SEVERITY_ORDER.get(args.severity, 3)
            classified["results"] = [
                r for r in classified["results"]
                if SEVERITY_ORDER.get(r["severity"], 3) <= min_sev
            ]
            classified["total_findings"] = sum(r["match_count"] for r in classified["results"])
            classified["severity_counts"] = {}
            for r in classified["results"]:
                classified["severity_counts"][r["severity"]] = \
                    classified["severity_counts"].get(r["severity"], 0) + r["match_count"]
            classified["has_critical"] = classified["severity_counts"].get("critical", 0) > 0

        classified["package"] = raw_results.get("package", "")

        if os.path.isdir(runner.tempdir):
            shutil.rmtree(runner.tempdir)

        elapsed = int((time.time() - start) * 1000)
        return _json_response(ok=True, data=classified, duration_ms=elapsed)
    except SystemExit as e:
        return _json_response(ok=False, error=f"Scan aborted (exit code {e.code})", error_code="SCAN_FAILED")
    except Exception as e:
        return _json_response(ok=False, error=str(e), error_code="SCAN_FAILED")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        if original_input is not None:
            __builtins__.input = original_input
        if runner and hasattr(runner, "fileout"):
            try:
                runner.fileout.close()
            except Exception:
                pass


# ─── patterns ───────────────────────────────────────────────────

def cmd_patterns(args):
    pattern_file = args.pattern
    if not pattern_file:
        main_dir = os.path.dirname(os.path.abspath(__file__))
        pattern_file = os.path.join(main_dir, "config", "regexes.json")
    if not os.path.isfile(pattern_file):
        return _json_response(ok=False, error=f"Pattern file not found: {pattern_file}",
                              error_code="PATTERN_FILE_NOT_FOUND")
    try:
        with open(pattern_file, "r") as f:
            patterns = json.load(f)
        data = []
        for name, regex in patterns.items():
            entry = {
                "name": name, "severity": _get_severity(name),
                "type": "multi" if isinstance(regex, list) else "single",
                "pattern_count": len(regex) if isinstance(regex, list) else 1,
            }
            if args.verbose:
                entry["patterns"] = regex if isinstance(regex, list) else [regex]
            data.append(entry)
        data.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 3))
        return _json_response(ok=True, data={
            "source": pattern_file, "total_categories": len(data), "patterns": data,
        })
    except Exception as e:
        return _json_response(ok=False, error=str(e))


# ─── decompile ──────────────────────────────────────────────────

def cmd_decompile(args):
    if not os.path.isfile(args.file):
        return _json_response(ok=False, error=f"APK file not found: {args.file}", error_code="FILE_NOT_FOUND")
    jadx_path = _resolve_jadx()
    if not jadx_path or not os.path.isfile(jadx_path):
        return _json_response(ok=False, error="jadx not found. Run 'check' first.", error_code="JADX_NOT_FOUND")

    output_dir = args.output_dir
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="apkleaks-decompile-")

    cmd_parts = [jadx_path, args.file, "-d", output_dir]
    if args.jadx_args:
        for part in args.jadx_args.split():
            if "=" in part:
                cmd_parts.extend(part.split("=", 1))
            else:
                cmd_parts.append(part)

    import shlex
    cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
    start = time.time()

    try:
        result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=600)
        elapsed = int((time.time() - start) * 1000)
        file_count = 0
        if os.path.isdir(output_dir):
            for _, _, files in os.walk(output_dir):
                file_count += len(files)
        data = {
            "output_dir": output_dir,
            "exit_code": result.returncode,
            "duration_ms": elapsed,
            "file_count": file_count,
        }
        if result.returncode != 0:
            data["stderr"] = result.stderr[:2000] if result.stderr else ""
            return _json_response(ok=False, error="jadx decompilation failed", error_code="JADX_FAILED", data=data)
        return _json_response(ok=True, data=data, duration_ms=elapsed)
    except subprocess.TimeoutExpired:
        return _json_response(ok=False, error="jadx decompilation timed out", error_code="JADX_TIMEOUT")
    except Exception as e:
        return _json_response(ok=False, error=str(e), error_code="JADX_FAILED")


# ─── search ─────────────────────────────────────────────────────

def cmd_search(args):
    if not os.path.isdir(args.dir):
        return _json_response(ok=False, error=f"Directory not found: {args.dir}", error_code="DIR_NOT_FOUND")
    try:
        compiled = re.compile(args.pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        return _json_response(ok=False, error=f"Invalid regex: {e}", error_code="INVALID_REGEX")

    file_type = args.type or "all"
    extensions = FILE_TYPE_EXTENSIONS.get(file_type) if file_type != "all" else None
    context_lines = args.context or 0
    limit = args.limit or 500
    start = time.time()
    matches = []
    seen = set()

    for root, _, files in os.walk(args.dir):
        for fname in files:
            if extensions and not fname.endswith(extensions):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                if compiled.search(line):
                    match_text = line.rstrip("\n\r")
                    dedup_key = (fpath, i + 1, match_text)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    entry = {
                        "file": os.path.relpath(fpath, args.dir),
                        "line": i + 1,
                        "match": match_text,
                    }
                    if context_lines > 0:
                        before_start = max(0, i - context_lines)
                        after_end = min(len(lines), i + context_lines + 1)
                        entry["context_before"] = [l.rstrip("\n\r") for l in lines[before_start:i]]
                        entry["context_after"] = [l.rstrip("\n\r") for l in lines[i + 1:after_end]]
                    matches.append(entry)
                    if len(matches) >= limit:
                        break
            if len(matches) >= limit:
                break
        if len(matches) >= limit:
            break

    elapsed = int((time.time() - start) * 1000)
    return _json_response(ok=True, data={
        "pattern": args.pattern,
        "type": file_type,
        "dir": args.dir,
        "total_matches": len(matches),
        "limit": limit,
        "context_lines": context_lines,
        "matches": matches,
    }, duration_ms=elapsed)


# ─── explain ────────────────────────────────────────────────────

def cmd_explain(args):
    category = args.category
    severity = _get_severity(category)
    description = EXPLANATIONS.get(category)

    if not description:
        # Check for partial match
        matches = [k for k in EXPLANATIONS if category.lower() in k.lower()]
        if matches:
            category = matches[0]
            severity = _get_severity(category)
            description = EXPLANATIONS[category]
        else:
            return _json_response(
                ok=False,
                error=f"No explanation found for '{args.category}'. Use 'patterns' to see available categories.",
                error_code="MISSING_ARG",
            )

    impact_map = {
        "critical": "Immediate credential compromise. Rotate and revoke exposed secrets without delay.",
        "high": "Significant security risk. Exposed credentials could lead to unauthorized access.",
        "medium": "Potential information disclosure. Review and restrict as needed.",
        "low": "Minor information exposure. Low direct risk but review for context.",
        "info": "Informational finding. No direct security impact but useful for reconnaissance.",
    }
    remediation_map = {
        "critical": "Rotate the exposed credential immediately. Move secrets to environment variables or a secrets manager. Audit access logs for unauthorized use.",
        "high": "Rotate the exposed credential. Move to secure storage. Review access logs.",
        "medium": "Review the finding in context. Move to configuration if appropriate. Consider restricting API key scope.",
        "low": "Review for sensitive context. Generally acceptable in client-side code but verify.",
        "info": "No immediate action required. Useful for understanding the app's attack surface.",
    }

    data = {
        "category": category,
        "severity": severity,
        "description": description,
        "impact": impact_map.get(severity, "Unknown severity level."),
        "remediation": remediation_map.get(severity, "Review the finding."),
    }
    return _json_response(ok=True, data=data)


# ─── mcp ────────────────────────────────────────────────────────

def cmd_mcp(args):
    """Run as MCP server over stdio (JSON-RPC style).

    Implements the MCP specification lifecycle:
      1. Client sends initialize -> Server responds with capabilities
      2. Client sends initialized notification -> Server is ready
      3. Client sends tools/list, tools/call, or notifications

    Also supports direct method dispatch for convenience.
    """
    initialized = False

    # Build a dispatch table mapping method names to (cmd_func, arg_extractor) pairs
    def _make_args_from_params(method, params):
        """Create a namespace object from JSON-RPC params for a cmd_* function."""
        params = params or {}
        class _Args:
            pass
        a = _Args()
        if method == "schema":
            pass  # no args
        elif method == "version":
            pass  # no args
        elif method == "check":
            a.file = params.get("file") or params.get("f")
        elif method == "info":
            a.file = params.get("file") or params.get("f")
        elif method == "scan":
            a.file = params.get("file") or params.get("f")
            a.pattern = params.get("pattern") or params.get("p")
            a.jadx_args = params.get("jadx_args") or params.get("a")
            a.severity = params.get("severity") or params.get("s")
            a.output = params.get("output") or params.get("o")
            a.json = params.get("json_output") or params.get("json", False)
        elif method == "patterns":
            a.pattern = params.get("pattern") or params.get("p")
            a.verbose = params.get("verbose") or params.get("v", False)
        elif method == "decompile":
            a.file = params.get("file") or params.get("f")
            a.output_dir = params.get("output_dir") or params.get("o")
            a.jadx_args = params.get("jadx_args") or params.get("a")
        elif method == "search":
            a.dir = params.get("dir") or params.get("d")
            a.pattern = params.get("pattern") or params.get("p")
            a.limit = params.get("limit") or params.get("l")
            a.type = params.get("type") or params.get("t")
            a.context = params.get("context") or params.get("c")
        elif method == "explain":
            a.category = params.get("category") or params.get("c")
        return a

    CMD_DISPATCH = {
        "schema": cmd_schema,
        "version": cmd_version,
        "check": cmd_check,
        "info": cmd_info,
        "scan": cmd_scan,
        "patterns": cmd_patterns,
        "decompile": cmd_decompile,
        "search": cmd_search,
        "explain": cmd_explain,
    }

    def handle_request(request):
        nonlocal initialized
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        # initialize — MCP lifecycle handshake (required first)
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                        "logging": {},
                    },
                    "serverInfo": {
                        "name": "apkleaks",
                        "version": VERSION,
                    },
                },
                "id": req_id,
            }

        # notifications/initialized — client confirms init complete
        if method == "notifications/initialized":
            initialized = True
            return None  # Notifications have no response

        # Ping — keep-alive, always respond
        if method == "ping":
            return {"jsonrpc": "2.0", "result": {}, "id": req_id}

        # tools/list — return tool definitions with rich schemas for AI
        if method == "tools/list":
            tools = [
                {
                    "name": "apkleaks_schema",
                    "description": "Discover all APKLeaks capabilities — returns tool metadata, subcommand definitions, and error codes. Call this first to understand what's available.",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                },
                {
                    "name": "apkleaks_version",
                    "description": "Show APKLeaks and Python version information",
                    "inputSchema": {"type": "object", "properties": {}, "required": []},
                },
                {
                    "name": "apkleaks_check",
                    "description": "Verify prerequisites (Python, jadx, pyaxmlparser) and optionally validate an APK file. Returns structured pass/fail for each dependency.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "description": "Path to APK file to validate (optional)"},
                        },
                        "required": [],
                    },
                },
                {
                    "name": "apkleaks_info",
                    "description": "Extract APK metadata without decompiling — package name, permissions (categorized), activities, services, SDK versions, app name. Uses pyaxmlparser for fast binary XML parsing.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "description": "Path to APK file"},
                        },
                        "required": ["file"],
                    },
                },
                {
                    "name": "apkleaks_scan",
                    "description": "Full security scan: decompile APK with jadx, then scan with 60+ regex patterns for leaked secrets (API keys, tokens, credentials, endpoints). Results classified by severity (critical/high/medium/low/info). Takes 30-180 seconds.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "description": "Path to APK file"},
                            "severity": {"type": "string", "description": "Filter findings by minimum severity", "enum": ["critical", "high", "medium", "low", "info"]},
                            "pattern": {"type": "string", "description": "Path to custom patterns JSON file (uses default 60+ patterns if not set)"},
                            "jadx_args": {"type": "string", "description": "Extra jadx disassembler arguments (e.g. '--threads-count 5 --deobf')"},
                            "output": {"type": "string", "description": "Path to save results file (auto-generated if not set)"},
                            "json_output": {"type": "boolean", "description": "Save results in JSON format instead of text", "default": False},
                        },
                        "required": ["file"],
                    },
                },
                {
                    "name": "apkleaks_patterns",
                    "description": "List all 60+ regex detection pattern categories with severity levels. Use verbose=true to see pattern counts and types.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "verbose": {"type": "boolean", "description": "Include pattern details (severity, type, count)", "default": False},
                        },
                        "required": [],
                    },
                },
                {
                    "name": "apkleaks_decompile",
                    "description": "Decompile APK to Java source code using jadx. Returns output directory path and decompiled file count. Takes 30-120 seconds.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "description": "Path to APK file"},
                            "output_dir": {"type": "string", "description": "Output directory for decompiled source (auto-generated temp dir if not set)"},
                            "jadx_args": {"type": "string", "description": "Extra jadx arguments (e.g. '--threads-count 5 --deobf')"},
                        },
                        "required": ["file"],
                    },
                },
                {
                    "name": "apkleaks_search",
                    "description": "Search decompiled Java/XML source with custom regex pattern. Supports file type filtering and context lines around matches.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "dir": {"type": "string", "description": "Path to decompiled source directory (from apkleaks_decompile output)"},
                            "pattern": {"type": "string", "description": "Regex pattern to search for"},
                            "type": {"type": "string", "description": "File type filter", "enum": ["java", "xml", "json", "smali", "all"], "default": "all"},
                            "context": {"type": "number", "description": "Number of context lines around each match", "default": 0},
                            "limit": {"type": "number", "description": "Maximum number of results to return", "default": 50},
                        },
                        "required": ["dir", "pattern"],
                    },
                },
                {
                    "name": "apkleaks_explain",
                    "description": "Explain what a finding category means — what it matches, why it matters (impact), and how to fix it (remediation). Use after scan to understand findings.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "category": {"type": "string", "description": "Finding category name (e.g. 'Amazon_AWS_Access_Key_ID', 'Slack_Token', 'Google_API_Key')"},
                        },
                        "required": ["category"],
                    },
                },
            ]
            return {"jsonrpc": "2.0", "result": {"tools": tools}, "id": req_id}


        # ── resources/list — expose readable resources ──
        if method == "resources/list":
            resources = [
                {
                    "uri": "apkleaks:///config/regexes",
                    "name": "Detection Patterns (regexes.json)",
                    "description": "All 60+ regex pattern definitions used by APKLeaks for secret scanning",
                    "mimeType": "application/json",
                },
                {
                    "uri": "apkleaks:///config/severity-map",
                    "name": "Severity Classification Map",
                    "description": "Maps each finding category to its severity level (critical/high/medium/low/info)",
                    "mimeType": "application/json",
                },
                {
                    "uri": "apkleaks:///config/explanations",
                    "name": "Finding Explanations",
                    "description": "Human-readable explanations for each finding category — what it matches, impact, and remediation",
                    "mimeType": "application/json",
                },
            ]
            return {"jsonrpc": "2.0", "result": {"resources": resources}, "id": req_id}


        # ── resources/read — read a resource by URI ──
        if method == "resources/read":
            uri = params.get("uri", "")
            if uri == "apkleaks:///config/regexes":
                main_dir = os.path.dirname(os.path.abspath(__file__))
                regexes_path = os.path.join(main_dir, "config", "regexes.json")
                try:
                    with open(regexes_path, "r") as f:
                        content = f.read()
                    return {"jsonrpc": "2.0", "result": {
                        "contents": [{"uri": uri, "mimeType": "application/json", "text": content}],
                    }, "id": req_id}
                except Exception as e:
                    return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": req_id}
            elif uri == "apkleaks:///config/severity-map":
                return {"jsonrpc": "2.0", "result": {
                    "contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(SEVERITY_MAP)}],
                }, "id": req_id}
            elif uri == "apkleaks:///config/explanations":
                return {"jsonrpc": "2.0", "result": {
                    "contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(EXPLANATIONS)}],
                }, "id": req_id}
            # Dynamic resource: read a file from decompiled source
            elif uri.startswith("apkleaks:///source/"):
                file_path = uri[len("apkleaks:///source/"):]
                if not os.path.isfile(file_path):
                    return {"jsonrpc": "2.0", "error": {"code": -32000, "message": f"File not found: {file_path}"}, "id": req_id}
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()
                    mime = "text/plain"
                    if file_path.endswith(".java"):
                        mime = "text/x-java"
                    elif file_path.endswith(".xml"):
                        mime = "text/xml"
                    elif file_path.endswith(".json"):
                        mime = "application/json"
                    elif file_path.endswith(".smali"):
                        mime = "text/plain"
                    return {"jsonrpc": "2.0", "result": {
                        "contents": [{"uri": uri, "mimeType": mime, "text": content}],
                    }, "id": req_id}
                except Exception as e:
                    return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": req_id}
            else:
                return {"jsonrpc": "2.0", "error": {"code": -32000, "message": f"Unknown resource URI: {uri}"}, "id": req_id}


        # ── prompts/list — pre-built analysis templates ──
        if method == "prompts/list":
            prompts = [
                {
                    "name": "security-audit",
                    "description": "Full security audit of an APK — scan, extract metadata, identify critical findings, and generate remediation advice",
                    "arguments": [
                        {"name": "apk_path", "description": "Path to the APK file to audit", "required": True},
                        {"name": "severity_filter", "description": "Minimum severity to report (critical/high/medium/low/info)", "required": False},
                    ],
                },
                {
                    "name": "credential-rotation",
                    "description": "Analyze leaked credentials and generate a credential rotation plan — identify what to revoke, what to rotate, and what to monitor",
                    "arguments": [
                        {"name": "apk_path", "description": "Path to the APK file", "required": True},
                    ],
                },
                {
                    "name": "api-inventory",
                    "description": "Extract and catalog all API endpoints, URLs, and backend infrastructure exposed in the APK source code",
                    "arguments": [
                        {"name": "apk_path", "description": "Path to the APK file", "required": True},
                    ],
                },
                {
                    "name": "permission-risk",
                    "description": "Analyze APK permissions and assess risk level — identify dangerous permission combinations and suggest mitigations",
                    "arguments": [
                        {"name": "apk_path", "description": "Path to the APK file", "required": True},
                    ],
                },
            ]
            return {"jsonrpc": "2.0", "result": {"prompts": prompts}, "id": req_id}


        # ── prompts/get — return prompt text with arguments substituted ──
        if method == "prompts/get":
            prompt_name = params.get("name", "")
            prompt_args = params.get("arguments", {})
            apk_path = prompt_args.get("apk_path", "PATH_TO_APK")
            sev_filter = prompt_args.get("severity_filter", "medium")

            PROMPT_TEMPLATES = {
                "security-audit": [
                    {"role": "user", "content": {
                        "type": "text",
                        "text": f"""Perform a full security audit of the APK at '{apk_path}'.

Step 1: Run apkleaks_check to verify prerequisites
Step 2: Run apkleaks_info to extract metadata (package, permissions, activities)
Step 3: Run apkleaks_scan with severity_filter='{sev_filter}' to find leaked secrets
Step 4: For each critical/high finding, run apkleaks_explain to understand impact
Step 5: Summarize all findings in a structured audit report with:
  - App metadata (package, version, permissions)
  - Critical findings (what was leaked, where, impact)
  - Remediation actions (rotate credentials, remove hardcoded keys)
  - Risk rating (Critical/High/Medium/Low based on findings)""",
                    }},
                ],
                "credential-rotation": [
                    {"role": "user", "content": {
                        "type": "text",
                        "text": f"""Analyze the APK at '{apk_path}' and generate a credential rotation plan.

Step 1: Run apkleaks_scan to find all leaked credentials
Step 2: For each finding category, run apkleaks_explain to understand what was leaked
Step 3: Generate a rotation plan with:
  - Credential type (AWS key, Stripe key, JWT, etc.)
  - Rotation action (revoke, rotate, regenerate)
  - Rotation URL (where to perform the action)
  - Monitoring action (what to watch after rotation)
  - Priority (Critical = immediate, High = within 24h, Medium = within 1 week)""",
                    }},
                ],
                "api-inventory": [
                    {"role": "user", "content": {
                        "type": "text",
                        "text": f"""Extract and catalog all API endpoints from the APK at '{apk_path}'.

Step 1: Run apkleaks_decompile to get the Java source
Step 2: Run apkleaks_search on the decompiled dir with pattern for URLs and endpoints
Step 3: Catalog each finding as:
  - Endpoint URL
  - HTTP method (if identifiable from surrounding code)
  - Authentication requirement (if identifiable)
  - Data exposure risk (what data this endpoint handles)
Step 4: Identify backend infrastructure domains and IPs""",
                    }},
                ],
                "permission-risk": [
                    {"role": "user", "content": {
                        "type": "text",
                        "text": f"""Analyze the permissions of the APK at '{apk_path}' and assess risk.

Step 1: Run apkleaks_info to get the permission list
Step 2: Categorize permissions by risk level:
  - Dangerous: CAMERA, MICROPHONE, LOCATION, READ_CONTACTS, etc.
  - Moderate: INTERNET, ACCESS_NETWORK_STATE, etc.
  - Low: VIBRATE, WAKE_LOCK, etc.
Step 3: Identify dangerous combinations (e.g. CAMERA + INTERNET = photo exfiltration)
Step 4: Assess overall risk and suggest permission reduction""",
                    }},
                ],
            }

            if prompt_name not in PROMPT_TEMPLATES:
                return {"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Unknown prompt: {prompt_name}"}, "id": req_id}

            return {"jsonrpc": "2.0", "result": {
                "description": f"Pre-built template: {prompt_name}",
                "messages": PROMPT_TEMPLATES[prompt_name],
            }, "id": req_id}


        # ── logging/setLevel — accept log level from client ──
        if method == "logging/setLevel":
            # Accept but don't act on it — we already silence logs in scan
            return {"jsonrpc": "2.0", "result": {}, "id": req_id}

        # tools/call — dispatch to the named subcommand
        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            # Map apkleaks_* tool names to internal cmd_* functions
            MCP_TOOL_MAP = {
                "apkleaks_schema": "schema",
                "apkleaks_version": "version",
                "apkleaks_check": "check",
                "apkleaks_info": "info",
                "apkleaks_scan": "scan",
                "apkleaks_patterns": "patterns",
                "apkleaks_decompile": "decompile",
                "apkleaks_search": "search",
                "apkleaks_explain": "explain",
            }
            internal_name = MCP_TOOL_MAP.get(tool_name, tool_name)
            if internal_name not in CMD_DISPATCH:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                    "id": req_id,
                }
            try:
                a = _make_args_from_params(internal_name, tool_args)
                result = CMD_DISPATCH[internal_name](a)
                # Return MCP CallToolResult format: {content: [{type: "text", text: "..."}]}
                is_error = not result.get("ok", True)
                call_result = {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}],
                    "isError": is_error,
                }
                return {"jsonrpc": "2.0", "result": call_result, "id": req_id}
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(e)})}],
                        "isError": True,
                    },
                    "id": req_id,
                }

        # Direct method dispatch (method name = subcommand name)
        if method in CMD_DISPATCH:
            try:
                a = _make_args_from_params(method, params)
                result = CMD_DISPATCH[method](a)
                return {"jsonrpc": "2.0", "result": result, "id": req_id}
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(e)},
                    "id": req_id,
                }

        return {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": f"Method not found: {method}"},
            "id": req_id,
        }

    # Main loop: read JSON-RPC requests from stdin, one per line
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            response = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": f"Parse error: {e}"},
                "id": None,
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue
        response = handle_request(request)
        if response is None:
            # Notification — no response required (e.g. notifications/initialized)
            continue
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


# ─── main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="apkleaks-ai-cli",
        description="APKLeaks AI-CLI — Structured JSON interface for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # schema
    p_schema = subparsers.add_parser("schema", help="Output tool schema definition (AI self-discovery)")
    p_schema.set_defaults(func=cmd_schema)

    # version
    p_version = subparsers.add_parser("version", help="Show version information")
    p_version.set_defaults(func=cmd_version)

    # check
    p_check = subparsers.add_parser("check", help="Verify prerequisites and APK validity")
    p_check.add_argument("-f", "--file", dest="file", default=None, help="APK file to validate")
    p_check.set_defaults(func=cmd_check)

    # info
    p_info = subparsers.add_parser("info", help="Extract APK metadata")
    p_info.add_argument("-f", "--file", dest="file", required=True, help="APK file path")
    p_info.set_defaults(func=cmd_info)

    # scan
    p_scan = subparsers.add_parser("scan", help="Full scan: decompile + regex pattern matching")
    p_scan.add_argument("-f", "--file", dest="file", required=True, help="APK file path")
    p_scan.add_argument("-p", "--pattern", dest="pattern", default=None, help="Custom pattern file")
    p_scan.add_argument("-a", "--args", dest="jadx_args", default=None, help="Additional jadx arguments")
    p_scan.add_argument("-s", "--severity", dest="severity", default=None,
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Filter results by minimum severity")
    p_scan.set_defaults(func=cmd_scan)

    # patterns
    p_patterns = subparsers.add_parser("patterns", help="List regex detection patterns")
    p_patterns.add_argument("-p", "--pattern", dest="pattern", default=None, help="Custom pattern file path")
    p_patterns.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Show regex patterns")
    p_patterns.set_defaults(func=cmd_patterns)

    # decompile
    p_decompile = subparsers.add_parser("decompile", help="Decompile APK to Java source")
    p_decompile.add_argument("-f", "--file", dest="file", required=True, help="APK file path")
    p_decompile.add_argument("-o", "--output", dest="output_dir", default=None, help="Output directory")
    p_decompile.add_argument("-a", "--args", dest="jadx_args", default=None, help="Additional jadx arguments")
    p_decompile.set_defaults(func=cmd_decompile)

    # search
    p_search = subparsers.add_parser("search", help="Search decompiled source with regex")
    p_search.add_argument("-d", "--dir", dest="dir", required=True, help="Decompiled source directory")
    p_search.add_argument("-p", "--pattern", dest="pattern", required=True, help="Regex pattern to search")
    p_search.add_argument("-l", "--limit", dest="limit", type=int, default=500, help="Max results")
    p_search.add_argument("-t", "--type", dest="type", default="all",
                          choices=["java", "xml", "json", "smali", "all"], help="File type filter")
    p_search.add_argument("-c", "--context", dest="context", type=int, default=0,
                          help="Context lines before/after match")
    p_search.set_defaults(func=cmd_search)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain a finding category")
    p_explain.add_argument("-c", "--category", dest="category", required=True,
                           help="Finding category name to explain")
    p_explain.set_defaults(func=cmd_explain)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run as MCP server over stdio")
    p_mcp.set_defaults(func=cmd_mcp)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = args.func(args)
    if result is not None:
        _write_json(result)


if __name__ == "__main__":
    main()