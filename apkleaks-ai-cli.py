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
    "AWS_API_Key": "critical", "AWS_Secret_Access_Key": "critical",
    "Artifactory_API_Token": "high",
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
    # ── Cloud Providers ──
    "Microsoft_Azure_Client_Secret": "critical",
    "Microsoft_Azure_Connection_String": "critical",
    "DigitalOcean_API_Token": "critical", "DigitalOcean_OAuth_Token": "high",
    "Alibaba_Access_Key_ID": "critical", "Alibaba_Access_Key_Secret": "critical",
    "Tencent_Cloud_Secret_ID": "critical", "Tencent_Cloud_Secret_Key": "critical",
    # ── AI/LLM Providers ──
    "OpenAI_API_Key": "critical", "Anthropic_API_Key": "critical",
    # ── Messaging/Communication ──
    "SendGrid_API_Key": "critical", "Telegram_BOT_Token": "high",
    "Twilio_Account_SID": "high",
    # ── E-Commerce/Payment ──
    "Shopify_Access_Token": "critical", "Shopify_Custom_App_Access_Token": "critical",
    "Stripe_Public_Key": "medium", "Stripe_Test_API_Key": "medium",
    # ── Storage/File ──
    "Dropbox_API_Key": "high",
    # ── DevOps/CI/CD ──
    "GitHub_OAuth_Access_Token": "critical", "GitHub_Personal_Access_Token": "critical",
    "GitHub_Fine_Grained_PAT": "critical", "GitLab_Personal_Access_Token": "critical",
    "NuGet_API_Key": "high", "NPM_Access_Token": "high",
    "Buildkite_API_Token": "high",
    # ── Observability/Monitoring ──
    "Sentry_DSN": "high", "Datadog_API_Key": "high", "NewRelic_API_Key": "high",
    # ── CDN/Edge ──
    "Cloudflare_API_Key": "critical", "Cloudflare_Origin_CA_Key": "critical",
    "Fastly_API_Token": "high",
    # ── Hosting/Serverless ──
    "Vercel_Access_Token": "high", "Netlify_Access_Token": "high",
    "Heroku_OAuth_Token": "high",
    # ── Identity/Auth ──
    "Okta_API_Token": "critical",
    # ── Maps/Location ──
    "Mapbox_API_Token": "high",
    # ── Google Extended ──
    "Google_Recaptcha_Secret": "high",
    # ── Generic Patterns (Android-focused) ──
    "Generic_Token": "medium", "Generic_Password": "critical",
    "Private_Key_Generic": "critical", "Android_Keystore_Password": "critical",
    # ── Other ──
    "Linear_API_Key": "high",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

EXPLANATIONS = {
    # ── AWS / Cloud ──
    "Amazon_AWS_Access_Key_ID": "AWS Access Key IDs (AKIA prefix) identify an IAM user. If found with the secret key, an attacker gets full AWS access. Rotate immediately.",
    "Amazon_AWS_S3_Bucket": "S3 bucket URLs may expose stored data. Check for public access. Misconfigured buckets are a common data leak vector.",
    "AWS_API_Key": "AWS API keys provide access to Amazon Web Services. Compromised keys allow attackers to access resources or incur charges.",
    "AWS_Secret_Access_Key": "AWS Secret Access Keys are long-term IAM credentials (typically 40-character base64). Paired with an Access Key ID they grant full account access. Rotate in IAM immediately and prefer temporary credentials.",
    "Microsoft_Azure_Client_Secret": "Azure client secrets authenticate applications to Microsoft Entra ID (Azure AD). A leaked secret allows impersonation of the app and access to all granted resources. Rotate in the Azure Portal under App Registrations.",
    "Microsoft_Azure_Connection_String": "Azure Storage connection strings contain the account name and key. Full access to the storage account (blobs, queues, tables, files). Rotate in the Azure Portal under Storage Account > Access Keys.",
    "DigitalOcean_API_Token": "DigitalOcean API tokens (dop_v1_ prefix) provide full access to Droplets, Spaces, and other DO resources. Revoke at cloud.digitalocean.com/account/api/tokens.",
    "DigitalOcean_OAuth_Token": "DigitalOcean OAuth tokens provide scoped access to DO resources on behalf of a user. Check token scope and revoke if compromised.",
    "Alibaba_Access_Key_ID": "Alibaba Cloud AccessKey IDs (LTAI prefix) identify an Alibaba Cloud account. If paired with the AccessKey Secret, an attacker gets full access to Alibaba Cloud services (ECS, OSS, RAM).",
    "Alibaba_Access_Key_Secret": "Alibaba Cloud AccessKey Secrets authenticate requests. Combined with the AccessKey ID, this grants full account access. Rotate immediately in the RAM console.",
    "Tencent_Cloud_Secret_ID": "Tencent Cloud SecretIds (AKID prefix) identify API users. Combined with the SecretKey, grants access to Tencent Cloud services (CVM, COS, CBS).",
    "Tencent_Cloud_Secret_Key": "Tencent Cloud SecretKeys authenticate API requests. Leaked key + SecretID = full account compromise. Rotate in the Tencent Cloud console.",
    # ── AI / LLM ──
    "OpenAI_API_Key": "OpenAI API keys (sk-...T3BlbkFJ... prefix) provide access to GPT, DALL-E, and other OpenAI services. Leaked keys can be used to incur charges or extract sensitive data sent to the API. Revoke at platform.openai.com/api-keys.",
    "Anthropic_API_Key": "Anthropic API keys (sk-ant-api03- prefix) provide access to Claude and other Anthropic AI services. Leaked keys can incur significant charges. Revoke at console.anthropic.com.",
    # ── Authorization ──
    "Authorization_Bearer": "OAuth 2.0 bearer tokens grant the same access as the token holder. Check token expiration and revocation.",
    "Authorization_Basic": "Base64-encoded username:password. Easily decoded. Can authenticate to the associated service.",
    "Basic_Auth_Credentials": "Hardcoded username:password in source code. Not obfuscated, trivially extracted from APK.",
    # ── Messaging / Communication ──
    "SendGrid_API_Key": "SendGrid API keys (SG. prefix) provide access to send emails on behalf of the account. Leaked keys can be used to send phishing emails or spam. Revoke at app.sendgrid.com/settings/api-keys.",
    "Telegram_BOT_Token": "Telegram bot tokens (format: <bot_id>:AA...) allow full control of the bot — sending/receiving messages, accessing group chats. Revoke via @BotFather on Telegram.",
    "Twilio_API_Key": "Twilio API keys (SK prefix) authenticate to the Twilio API for SMS, voice, and other communications. Revoke at twilio.com/console.",
    "Twilio_Account_SID": "Twilio Account SIDs (AC prefix) identify the account. Combined with an auth token, grants full access. Check for accompanying credentials.",
    "Twitter_Access_Token": "Twitter/X access tokens provide API access to post tweets, read DMs, and manage the account. Leaked tokens allow full account takeover. Revoke at developer.x.com/en/portal/dashboard.",
    "Twitter_ClientID": "Twitter/X client IDs identify the application. Not a secret alone, but combined with a leaked client secret, allows API impersonation. Verify no secret is also exposed.",
    "Twitter_OAuth": "Twitter/X OAuth tokens in source code can be used to impersonate users or access their account. Check token scope and revoke the app secret.",
    "Twitter_Secret_Key": "Twitter/X consumer secret keys (API secret) are used to authenticate API requests. Leakage allows impersonation of the Twitter app. Regenerate at developer.x.com/en/portal/dashboard.",
    # ── E-Commerce / Payment ──
    "Shopify_Access_Token": "Shopify access tokens (shpat_ prefix) provide full API access to a Shopify store — products, orders, customers, and payments. Revoke in the Shopify admin under Apps.",
    "Shopify_Custom_App_Access_Token": "Shopify custom app tokens (shca_ prefix) provide scoped API access. Still dangerous if leaked — can access store data within the granted scopes.",
    "Stripe_API_Key": "Stripe keys (sk_live_) provide full payment access. Can issue refunds, access customer data. Revoke immediately.",
    "Stripe_Public_Key": "Stripe publishable keys (pk_live_) are designed for client-side use and are less sensitive than secret keys. However, they reveal the Stripe account and should not be used server-side.",
    "Stripe_Test_API_Key": "Stripe test keys (sk_test_) are for sandbox testing. Lower risk than live keys but should still not be exposed in production builds.",
    "Stripe_Restricted_API_Key": "Stripe restricted keys (rk_live_) have limited permissions but still pose a risk based on their granted scopes. Rotate at dashboard.stripe.com/apikeys.",
    "Square_Access_Token": "Square access tokens (sq0atp- prefix) provide full API access to Square merchant data — payments, inventory, customers. Revoke at developer.squareup.com.",
    "Square_OAuth_Secret": "Square OAuth secrets (sq0csp- prefix) are used to obtain access tokens. Leakage allows token generation for any authorized user. Critical to rotate.",
    "PayPal_Braintree_Access_Token": "PayPal/Braintree access tokens provide payment processing access. Can create transactions, access vaulted payment methods. Revoke in the Braintree control panel.",
    # ── Facebook ──
    "Facebook_Access_Token": "Facebook access tokens (EAACEdEose0cBA prefix) provide access to the user's Facebook data based on the token's permissions. Revoke by changing the Facebook app secret.",
    "Facebook_ClientID": "Facebook Client IDs identify the app but are not secrets by themselves. However, combined with a leaked secret key, they enable full API access.",
    "Facebook_OAuth": "Facebook OAuth tokens in source code can be used to impersonate users or access their Facebook data. Check token scope and revoke the app secret.",
    "Facebook_Secret_Key": "Facebook Secret Keys (App Secrets) are used to authenticate server-side API requests. Leakage allows impersonation of the Facebook app. Reset at developers.facebook.com.",
    # ── Firebase / Google ──
    "Firebase": "Firebase URLs (firebaseio.com) often have weak security rules. Check for unauthenticated read/write access.",
    "Google_API_Key": "Google API keys (AIza prefix) for Maps, YouTube, etc. Unrestricted keys can be abused for some services.",
    "Google_Cloud_Platform_OAuth": "Google Cloud Platform OAuth client IDs identify the application. Combined with the client secret, allows OAuth flow abuse. Check if client secret is also exposed.",
    "Google_Cloud_Platform_Service_Account": "GCP service account keys provide full project access. Fully compromised if found.",
    "Google_OAuth_Access_Token": "Google OAuth access tokens (ya29. prefix) grant access to the user's Google account within the token's scope. Check for refresh tokens which are longer-lived.",
    "Google_Recaptcha_Secret": "Google reCAPTCHA secret keys verify reCAPTCHA challenges server-side. Leakage allows bypassing CAPTCHA verification. Regenerate at google.com/recaptcha/admin.",
    # ── GitHub / Git ──
    "GitHub": "Generic GitHub tokens found in source code. Could be personal access tokens, OAuth tokens, or other credentials. Verify scope and revoke at github.com/settings/tokens.",
    "GitHub_Access_Token": "GitHub credentials in URL format (user:token@github.com). Provides repository access. Revoke immediately and switch to SSH keys or fine-grained PATs.",
    "GitHub_OAuth_Access_Token": "GitHub OAuth tokens (gho_ prefix) grant API access on behalf of a user. Scope determines access level. Revoke at github.com/settings/tokens.",
    "GitHub_Personal_Access_Token": "GitHub PATs (ghp_ prefix) provide API access to repos, orgs, and user data. Scope determines access level. Revoke at github.com/settings/tokens.",
    "GitHub_Fine_Grained_PAT": "GitHub fine-grained PATs (github_pat_ prefix) provide scoped access to specific repositories. More restrictive than classic PATs but still dangerous if leaked. Revoke immediately.",
    "GitLab_Personal_Access_Token": "GitLab PATs (glpat- prefix) provide API access to GitLab projects, CI/CD pipelines, and registry. Revoke at gitlab.com/-/user_settings/personal_access_tokens.",
    # ── Generic ──
    "Generic_API_Key": "Matches common API key patterns. Could be for any service. Verify by testing against known API endpoints.",
    "Generic_Secret": "Matches common secret/password patterns. Check surrounding code for which service uses this secret.",
    "Generic_Token": "Matches hardcoded token variables (access_token, auth_token, refresh_token) in source code. Verify the token's scope and revoke if active.",
    "Generic_Password": "Matches hardcoded password assignments in source code. Very common in Android apps. Even if obfuscated, the actual value is recoverable from the APK.",
    # ── Identity / Auth ──
    "Okta_API_Token": "Okta API tokens provide access to the Okta identity management platform — user management, SSO, MFA. Leaked tokens can compromise the entire organization's identity. Revoke at <your-org>.okta.com/admin/api/tokens.",
    # ── Infrastructure ──
    "Artifactory_API_Token": "JFrog Artifactory API tokens (AKC prefix) provide access to artifact repositories. Can be used to publish malicious packages or steal proprietary binaries.",
    "Artifactory_Password": "Artifactory passwords (AP prefix) provide full access to Artifactory. More sensitive than API tokens. Change immediately.",
    "Cloudinary_Basic_Auth": "Cloudinary URLs embed the API key and secret (cloudinary://key:secret@cloud). Provides full access to media asset management. Rotate in the Cloudinary dashboard.",
    # ── CDN / Edge ──
    "Cloudflare_API_Key": "Cloudflare API keys provide access to DNS, caching, WAF, and other Cloudflare services. Can be used to redirect traffic or disable security features. Revoke at dash.cloudflare.com/profile/api-tokens.",
    "Cloudflare_Origin_CA_Key": "Cloudflare Origin CA keys are used for origin server TLS. Leakage allows decryption of traffic between Cloudflare and the origin. Rotate at dash.cloudflare.com/ssl-tls/origin.",
    "Fastly_API_Token": "Fastly API tokens provide access to CDN configuration — caching rules, origins, and TLS. Can be used to redirect or intercept traffic. Revoke at manage.fastly.com/account/personal/tokens.",
    # ── Hosting / Serverless ──
    "Heroku_API_Key": "Heroku API keys found in source code. Grants access to Heroku apps, config vars (which often contain database URLs and secrets). Revoke at dashboard.heroku.com/account.",
    "Heroku_OAuth_Token": "Heroku OAuth tokens provide scoped access to Heroku on behalf of a user. Check token scope and revoke if compromised.",
    "Vercel_Access_Token": "Vercel access tokens provide access to deployments, environment variables, and project settings. Can be used to deploy malicious code. Revoke at vercel.com/account/tokens.",
    "Netlify_Access_Token": "Netlify access tokens provide access to site deployments, forms, and identity. Can be used to deploy malicious content. Revoke at app.netlify.com/user/applications.",
    # ── Monitoring / Observability ──
    "Sentry_DSN": "Sentry DSNs expose the project ID and key for error reporting. While public DSNs are intended for client-side use, they can be abused to inject false error reports. Check for private keys.",
    "Datadog_API_Key": "Datadog API keys send metrics and logs to Datadog. Leakage allows data injection or exfiltration of monitoring data. Revoke at app.datadoghq.com/organization-settings/api-keys.",
    "NewRelic_API_Key": "New Relic API keys provide access to APM data, dashboards, and alerting. Can be used to manipulate monitoring data or hide attacks. Revoke at one.newrelic.com/launcher/api-keys-ui.api-keys-launcher.",
    # ── DevOps / Package Registries ──
    "NuGet_API_Key": "NuGet API keys (oy2 prefix) provide access to push packages to nuget.org. Can be used to publish malicious packages. Revoke at nuget.org/account/apikeys.",
    "NPM_Access_Token": "NPM access tokens in .npmrc files provide access to publish packages or access private packages. Can be used for supply chain attacks. Revoke at npmjs.com/settings/tokens.",
    "Buildkite_API_Token": "Buildkite API tokens (bk prefix) provide access to CI/CD pipelines, build artifacts, and agent configuration. Can be used to inject malicious code into builds. Revoke at buildkite.com/user/api-access-tokens.",
    # ── Private Keys ──
    "PGP_private_key_block": "PGP private keys decrypt messages and sign as key owner. All encrypted communications compromised.",
    "RSA_Private_Key": "RSA private keys decrypt TLS traffic and impersonate key owner. May be used for cert pinning — extract for Frida MITM.",
    "SSH_DSA_Private_Key": "SSH DSA private keys authenticate to servers. Unprotected keys grant immediate server access.",
    "SSH_EC_Private_Key": "SSH EC private keys (Ed25519/ECDSA) authenticate to servers. Leaked key = full credential compromise.",
    "Private_Key_Generic": "Generic private key header detected. Covers RSA, DSA, EC, and OpenSSH key types. Full credential compromise if the complete key is present.",
    # ── Android-Specific ──
    "Android_Keystore_Password": "Android keystore/signing passwords (keyPassword, storePassword) in Gradle files allow signing malicious APKs with the same key. This enables app updates that bypass verification. Move to environment variables or local.properties (not in VCS).",
    # ── Other Services ──
    "Discord_BOT_Token": "Discord bot tokens provide full control of the bot — sending messages, joining servers, accessing guild data. Revoke at discord.com/developers/applications.",
    "Slack_Token": "Slack tokens (xoxp-/xoxb-/xoxo- prefix) provide access to Slack workspaces. xoxp- = user token, xoxb- = bot token. Revoke at api.slack.com/authentication/token-types.",
    "Slack_Webhook": "Slack webhook URLs allow posting messages to a channel. Cannot read messages but can spam or phish via the webhook. Revoke by deleting the webhook in Slack app settings.",
    "Dropbox_API_Key": "Dropbox API keys (sl. prefix) provide access to files in the linked Dropbox account. Can read, write, or delete files. Revoke at dropbox.com/account/connected_apps.",
    "Dropbox_Long_Lived_Access_Token": "Dropbox long-lived access tokens found in source code. These tokens don't expire and provide persistent file access. Revoke by unlinking the app.",
    "Linear_API_Key": "Linear API keys (lin_api_ prefix) provide access to project management data — issues, projects, teams. Can be used to exfiltrate project data or manipulate workflows. Revoke at linear.app/settings/api.",
    "Mapbox_API_Token": "Mapbox API tokens (pk. prefix) provide access to Mapbox mapping services. Unrestricted tokens can be abused for geocoding or map tile requests, incurring charges. Set URL restrictions on the token.",
    "Square_Test_Access_Token": "Square test access tokens (sq0atb- prefix) are for sandbox testing. Lower risk than production tokens but should not be in production builds.",
    "PayPal_Client_ID": "PayPal client IDs identify the application. Not secret by itself but combined with a leaked secret, enables payment API access. Verify no secret is also exposed.",
    "Picatic_API_Key": "Picatic API keys (sk_live_ prefix) provide access to event management. Can access attendee data and ticket sales. Revoke in the Picatic dashboard.",
    "Twilio_API_Key": "Twilio API keys (SK prefix) authenticate API requests for SMS, voice, and other services. Combined with the account SID, grants full access. Revoke at twilio.com/console.",
    "MailChimp_API_Key": "MailChimp API keys provide access to mailing lists, campaigns, and subscriber data. Can be used to export email lists or send unauthorized campaigns. Revoke at mailchimp.com/account/api.",
    "Mailgun_API_Key": "Mailgun API keys (key- prefix) provide access to send and manage emails. Can be used to send phishing emails or spam. Revoke at mailgun.com/app/account/security/api_keys.",
    "LinkFinder": "URLs and API endpoints revealing backend infrastructure. Check for admin panels and unauthenticated APIs.",
    "JSON_Web_Token": "JWTs (eyJ prefix) contain encoded claims. If signing key is also found, tokens can be forged.",
    "Password_in_URL": "Passwords in URLs (user:pass@host) are logged in server logs and proxy caches. Change immediately.",
    # ── Informational / Low Risk ──
    "IP_Address": "IP addresses found in source code. May reveal internal infrastructure or backend server locations. Low direct risk but useful for reconnaissance.",
    "Mac_Address": "MAC addresses found in source code. Can be used for device tracking or network identification. Low direct risk.",
    "Mailto": "Email addresses found in source code (mailto: links). May reveal developer or support contact info. Low risk but useful for social engineering.",
    "DEFCON_CTF_Flag": "DEFCON CTF flag format (O{3}{...}) detected. Informational only — indicates CTF-related code or content.",
    "HackerOne_CTF_Flag": "HackerOne CTF flag format (h1CTF{...}) detected. Informational only — indicates CTF-related code or content.",
    "HackTheBox_CTF_Flag": "HackTheBox flag format (HackTheBox{...} or HTB{...}) detected. Informational only — indicates CTF-related code or content.",
    "TryHackMe_CTF_Flag": "TryHackMe flag format (TryHackMe{...} or THM{...}) detected. Informational only — indicates CTF-related code or content.",
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
    "UNKNOWN_CATEGORY": "The specified finding category is not recognized",
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
    """Get severity for a category, checking runtime rules first, then SEVERITY_MAP."""
    if category_name in _RUNTIME_RULES and "severity" in _RUNTIME_RULES[category_name]:
        return _RUNTIME_RULES[category_name]["severity"]
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
            {"name": "rule-add", "description": "Add a custom detection rule at runtime (in-memory)",
             "args": [{"name": "name", "flag": "-n", "type": "string", "required": True,
                        "description": "Rule name (e.g. My_Custom_Key)"},
                      {"name": "regex", "flag": "-r", "type": "string", "required": True,
                        "description": "Regex pattern string"},
                      {"name": "severity", "flag": "-s", "type": "string", "required": False,
                        "description": "Severity: critical/high/medium/low/info (default: medium)"}],
             "returns": "Added rule name, severity, regex preview, override warning if applicable"},
            {"name": "rule-remove", "description": "Remove a custom runtime rule (not built-in)",
             "args": [{"name": "name", "flag": "-n", "type": "string", "required": True,
                        "description": "Rule name to remove"}],
             "returns": "Removed rule name or error if not found / is built-in"},
            {"name": "rule-test", "description": "Test a regex pattern against sample text",
             "args": [{"name": "regex", "flag": "-r", "type": "string", "required": True,
                        "description": "Regex pattern to test"},
                      {"name": "text", "flag": "-t", "type": "string", "required": True,
                        "description": "Sample text to test against"}],
             "returns": "Regex validity, match results with groups, match count"},
        ],
        "severity_levels": {
            "critical": {"order": 0, "description": "Immediate credential compromise — rotate now"},
            "high": {"order": 1, "description": "Significant security risk — verify and restrict"},
            "medium": {"order": 2, "description": "Potential information disclosure — review context"},
            "low": {"order": 3, "description": "Minor information exposure — note for report"},
            "info": {"order": 4, "description": "Informational — no direct security impact"},
        },
        "coverage": {
            "total_patterns": len(SEVERITY_MAP),
            "categories_with_explanations": len(EXPLANATIONS),
            "explanation_coverage_pct": round(len(EXPLANATIONS) / len(SEVERITY_MAP) * 100, 1),
            "pattern_categories": {
                "cloud_providers": ["Amazon_AWS_Access_Key_ID", "Amazon_AWS_S3_Bucket", "AWS_API_Key",
                    "AWS_Secret_Access_Key",
                    "Microsoft_Azure_Client_Secret", "Microsoft_Azure_Connection_String",
                    "DigitalOcean_API_Token", "DigitalOcean_OAuth_Token",
                    "Alibaba_Access_Key_ID", "Alibaba_Access_Key_Secret",
                    "Tencent_Cloud_Secret_ID", "Tencent_Cloud_Secret_Key",
                    "Google_Cloud_Platform_OAuth", "Google_Cloud_Platform_Service_Account"],
                "ai_llm": ["OpenAI_API_Key", "Anthropic_API_Key"],
                "messaging": ["SendGrid_API_Key", "Telegram_BOT_Token", "Twilio_API_Key",
                    "Twilio_Account_SID", "MailChimp_API_Key", "Mailgun_API_Key", "Slack_Token",
                    "Slack_Webhook", "Discord_BOT_Token"],
                "ecommerce_payment": ["Shopify_Access_Token", "Shopify_Custom_App_Access_Token",
                    "Stripe_API_Key", "Stripe_Public_Key", "Stripe_Restricted_API_Key",
                    "Stripe_Test_API_Key", "Square_Access_Token", "Square_OAuth_Secret",
                    "PayPal_Braintree_Access_Token"],
                "devops_cicd": ["GitHub_Personal_Access_Token", "GitHub_OAuth_Access_Token",
                    "GitHub_Fine_Grained_PAT", "GitLab_Personal_Access_Token",
                    "NuGet_API_Key", "NPM_Access_Token", "Buildkite_API_Token"],
                "monitoring": ["Sentry_DSN", "Datadog_API_Key", "NewRelic_API_Key"],
                "cdn_edge": ["Cloudflare_API_Key", "Cloudflare_Origin_CA_Key", "Fastly_API_Token"],
                "hosting": ["Vercel_Access_Token", "Netlify_Access_Token",
                    "Heroku_API_Key", "Heroku_OAuth_Token"],
                "private_keys": ["RSA_Private_Key", "PGP_private_key_block",
                    "SSH_DSA_Private_Key", "SSH_EC_Private_Key", "Private_Key_Generic"],
                "android_specific": ["Android_Keystore_Password"],
                "generic": ["Generic_API_Key", "Generic_Secret", "Generic_Token",
                    "Generic_Password", "LinkFinder", "JSON_Web_Token"],
            },
        },
        "error_codes": ERROR_CODES,
        "response_format": {
            "success": {"ok": True, "data": "...", "timestamp": "ISO 8601", "duration_ms": "int (optional)",
                        "error_code": "string (optional, e.g. NO_FINDINGS)"},
            "error": {"ok": False, "error": "string", "error_code": "string", "timestamp": "ISO 8601",
                      "data": "object (optional, partial results)"},
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
    fake.output = getattr(args, "output", None)
    fake.args = args.jadx_args
    fake.json = True

    # If custom pattern file specified, use it directly.
    # Otherwise, merge runtime rules into a temp patterns file.
    merged_pattern_file = None
    if args.pattern:
        fake.pattern = args.pattern
    elif _RUNTIME_RULES:
        # Merge default patterns + runtime rules into a temp file
        merged, err = _get_merged_patterns()
        if err:
            return _json_response(ok=False, error=f"Failed to merge patterns: {err}", error_code="SCAN_FAILED")
        merged_pattern_file = tempfile.mktemp(suffix=".json", prefix="apkleaks-rules-")
        try:
            with open(merged_pattern_file, "w") as f:
                json.dump(merged, f, ensure_ascii=False)
        except Exception as e:
            return _json_response(ok=False, error=f"Failed to write merged patterns: {e}", error_code="SCAN_FAILED")
        fake.pattern = merged_pattern_file
    else:
        fake.pattern = args.pattern  # None → uses default

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

        # Save results to file if output path specified
        output_path = getattr(args, "output", None)
        if output_path:
            try:
                with open(output_path, "w") as f:
                    json.dump(classified, f, indent=2, ensure_ascii=False)
                classified["saved_to"] = output_path
            except Exception as e:
                classified["save_error"] = str(e)

        elapsed = int((time.time() - start) * 1000)
        error_code = "NO_FINDINGS" if classified["total_findings"] == 0 else None
        return _json_response(ok=True, data=classified, duration_ms=elapsed, error_code=error_code)
    except SystemExit as e:
        captured_err = sys.stderr.getvalue() if hasattr(sys.stderr, "getvalue") else ""
        detail = f"Scan aborted (exit code {e.code})"
        if captured_err:
            detail += f" | stderr: {captured_err[:500]}"
        return _json_response(ok=False, error=detail, error_code="SCAN_FAILED")
    except Exception as e:
        captured_err = sys.stderr.getvalue() if hasattr(sys.stderr, "getvalue") else ""
        detail = str(e)
        if captured_err:
            detail += f" | stderr: {captured_err[:500]}"
        return _json_response(ok=False, error=detail, error_code="SCAN_FAILED")
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
        # Clean up temp directory in all paths (success, error, exception)
        if runner and hasattr(runner, "tempdir") and os.path.isdir(runner.tempdir):
            try:
                shutil.rmtree(runner.tempdir)
            except Exception:
                pass
        # Clean up merged pattern temp file
        if merged_pattern_file and os.path.isfile(merged_pattern_file):
            try:
                os.remove(merged_pattern_file)
            except Exception:
                pass


# ─── patterns ───────────────────────────────────────────────────

def cmd_patterns(args):
    pattern_file = args.pattern
    tmp_file_to_cleanup = None
    if not pattern_file:
        # Use merged patterns (built-in + runtime rules) when no custom file specified
        if _RUNTIME_RULES:
            merged, err = _get_merged_patterns()
            if err:
                return _json_response(ok=False, error=err, error_code="PATTERN_FILE_ERROR")
            # Write merged to temp file for consistent reading
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="apkleaks-patterns-")
            json.dump(merged, tmp)
            tmp.close()
            pattern_file = tmp.name
            tmp_file_to_cleanup = tmp.name
        else:
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
            is_custom = name in _RUNTIME_RULES
            entry = {
                "name": name, "severity": _get_severity(name),
                "type": "multi" if isinstance(regex, list) else "single",
                "pattern_count": len(regex) if isinstance(regex, list) else 1,
                "is_custom": is_custom,
            }
            if args.verbose:
                entry["patterns"] = regex if isinstance(regex, list) else [regex]
            data.append(entry)
        data.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 3), x["name"]))
        custom_count = sum(1 for d in data if d["is_custom"])
        return _json_response(ok=True, data={
            "source": pattern_file, "total_categories": len(data),
            "builtin_categories": len(data) - custom_count,
            "custom_categories": custom_count,
            "patterns": data,
        })
    except Exception as e:
        return _json_response(ok=False, error=str(e))
    finally:
        if tmp_file_to_cleanup and os.path.isfile(tmp_file_to_cleanup):
            os.unlink(tmp_file_to_cleanup)


# ─── decompile ──────────────────────────────────────────────────

def cmd_decompile(args):
    if not os.path.isfile(args.file):
        return _json_response(ok=False, error=f"APK file not found: {args.file}", error_code="FILE_NOT_FOUND")
    jadx_path = _resolve_jadx()
    if not jadx_path or not os.path.isfile(jadx_path):
        return _json_response(ok=False, error="jadx not found. Run 'check' first.", error_code="JADX_NOT_FOUND")

    output_dir = args.output_dir
    auto_dir = False
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="apkleaks-decompile-")
        auto_dir = True

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

    def _cleanup_auto_dir():
        """Remove auto-created temp dir on failure to prevent disk leaks."""
        if auto_dir and os.path.isdir(output_dir):
            try:
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception:
                pass

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
            _cleanup_auto_dir()
            return _json_response(ok=False, error="jadx decompilation failed", error_code="JADX_FAILED", data=data)
        return _json_response(ok=True, data=data, duration_ms=elapsed)
    except subprocess.TimeoutExpired:
        _cleanup_auto_dir()
        return _json_response(ok=False, error="jadx decompilation timed out", error_code="JADX_TIMEOUT")
    except Exception as e:
        _cleanup_auto_dir()
        return _json_response(ok=False, error=str(e), error_code="JADX_FAILED")


# ─── search ─────────────────────────────────────────────────────

def cmd_search(args):
    if not os.path.isdir(args.dir):
        return _json_response(ok=False, error=f"Directory not found: {args.dir}", error_code="DIR_NOT_FOUND")
    try:
        compiled = re.compile(args.pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        return _json_response(ok=False, error=f"Invalid regex: {e}", error_code="INVALID_REGEX")

    file_type = args.type if args.type is not None else "all"
    extensions = FILE_TYPE_EXTENSIONS.get(file_type) if file_type != "all" else None
    context_lines = args.context if args.context is not None else 0
    limit = args.limit if args.limit is not None else 500
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
                error_code="UNKNOWN_CATEGORY",
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


# ─── runtime rules ────────────────────────────────────────────────

# Runtime custom rules added by AI agents via rule-add.
# These are merged into the default patterns during scan.
_RUNTIME_RULES = {}  # {name: {"regex": str|list, "severity": str}}


def _get_merged_patterns(custom_pattern_file=None):
    """Load default patterns and merge with runtime custom rules.

    Returns a dict of {name: regex_str | [regex_str, ...]}.
    If custom_pattern_file is provided, loads from that file as the base
    (ignoring runtime rules — explicit file overrides runtime additions).
    """
    if custom_pattern_file:
        if not os.path.isfile(custom_pattern_file):
            return None, f"Pattern file not found: {custom_pattern_file}"
        try:
            with open(custom_pattern_file, "r") as f:
                return json.load(f), None
        except Exception as e:
            return None, str(e)

    # Load default patterns
    main_dir = os.path.dirname(os.path.abspath(__file__))
    default_path = os.path.join(main_dir, "config", "regexes.json")
    try:
        with open(default_path, "r") as f:
            patterns = json.load(f)
    except Exception as e:
        return None, str(e)

    # Merge runtime rules
    for name, rule in _RUNTIME_RULES.items():
        patterns[name] = rule["regex"]

    return patterns, None


def cmd_rule_add(args):
    """Add a custom detection rule at runtime (no file modification).

    Rules persist for the current process lifetime only (in-memory).
    They are automatically merged into scans until removed.
    """
    name = args.name
    regex = args.regex
    severity = args.severity or "medium"

    # Validate regex
    try:
        if isinstance(regex, list):
            for r in regex:
                re.compile(r)
        else:
            re.compile(regex)
    except re.error as e:
        return _json_response(ok=False, error=f"Invalid regex: {e}", error_code="INVALID_REGEX")

    # Validate severity
    if severity not in SEVERITY_ORDER:
        return _json_response(ok=False,
                              error=f"Invalid severity: {severity}. Use: {', '.join(SEVERITY_ORDER.keys())}",
                              error_code="INVALID_REGEX")

    # Check if overriding a built-in rule
    is_override = name in SEVERITY_MAP
    was_custom = name in _RUNTIME_RULES

    _RUNTIME_RULES[name] = {"regex": regex, "severity": severity}

    data = {
        "name": name,
        "regex": regex,
        "severity": severity,
        "is_override": is_override,
        "was_updated": was_custom,
        "total_custom_rules": len(_RUNTIME_RULES),
    }
    return _json_response(ok=True, data=data)


def cmd_rule_remove(args):
    """Remove a custom detection rule from the runtime.

    Only removes rules added via rule-add (not built-in rules).
    """
    name = args.name

    if name not in _RUNTIME_RULES:
        # Check if it's a built-in rule
        if name in SEVERITY_MAP:
            return _json_response(
                ok=False,
                error=f"'{name}' is a built-in rule and cannot be removed. Use rule-add to override it instead.",
                error_code="UNKNOWN_CATEGORY",
            )
        return _json_response(
            ok=False,
            error=f"No custom rule found with name '{name}'.",
            error_code="UNKNOWN_CATEGORY",
        )

    removed = _RUNTIME_RULES.pop(name)
    data = {
        "removed": name,
        "removed_regex": removed["regex"],
        "removed_severity": removed["severity"],
        "remaining_custom_rules": len(_RUNTIME_RULES),
    }
    return _json_response(ok=True, data=data)


def cmd_rule_test(args):
    """Test a regex pattern against sample text without scanning an APK.

    Validates the regex, shows what it matches in the provided sample,
    and reports any issues. Useful for AI agents to validate rules
    before adding them via rule-add.
    """
    regex = args.regex
    # CLI uses --text/-t (args.text), MCP uses "sample" param (args.sample)
    sample = getattr(args, "text", None) or getattr(args, "sample", None) or ""
    category = getattr(args, "name", None) or "test_rule"
    severity = getattr(args, "severity", None) or "medium"

    # Validate regex
    try:
        compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        return _json_response(ok=False, error=f"Invalid regex: {e}", error_code="INVALID_REGEX")

    data = {
        "name": category,
        "regex": regex,
        "severity": severity,
        "is_valid": True,
    }

    # Test against sample if provided
    if sample:
        matches = compiled.findall(sample)
        data["sample"] = sample[:200]
        data["sample_matches"] = matches[:20]  # Cap at 20
        data["match_count"] = len(matches)
        data["has_matches"] = len(matches) > 0
    else:
        data["sample"] = None
        data["note"] = "Provide --text/-t to test matching behavior"

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
        """Create a namespace object from JSON-RPC params for a cmd_* function.

        Uses explicit None checks (not `or`) to avoid falsy-value bugs
        where limit=0, context=0, or empty string "" would be ignored.
        """
        params = params or {}
        def _first(*keys):
            """Return the first non-None value from params by key names."""
            for k in keys:
                v = params.get(k)
                if v is not None:
                    return v
            return None

        class _Args:
            pass
        a = _Args()
        if method == "schema":
            pass  # no args
        elif method == "version":
            pass  # no args
        elif method == "check":
            a.file = _first("file", "f")
        elif method == "info":
            a.file = _first("file", "f")
        elif method == "scan":
            a.file = _first("file", "f")
            a.pattern = _first("pattern", "p")
            a.jadx_args = _first("jadx_args", "a")
            a.severity = _first("severity", "s")
            a.output = _first("output", "o")
            a.json = _first("json_output", "json") or False
        elif method == "patterns":
            a.pattern = _first("pattern", "p")
            a.verbose = _first("verbose", "v") or False
        elif method == "decompile":
            a.file = _first("file", "f")
            a.output_dir = _first("output_dir", "o")
            a.jadx_args = _first("jadx_args", "a")
        elif method == "search":
            a.dir = _first("dir", "d")
            a.pattern = _first("pattern", "p")
            a.limit = _first("limit", "l")
            a.type = _first("type", "t")
            a.context = _first("context", "c")
        elif method == "explain":
            a.category = _first("category", "c")
        elif method == "rule_add":
            a.name = _first("name", "n")
            a.regex = _first("regex", "r")
            a.severity = _first("severity", "s")
        elif method == "rule_remove":
            a.name = _first("name", "n")
        elif method == "rule_test":
            a.name = _first("name", "n")
            a.regex = _first("regex", "r")
            a.sample = _first("sample", "s")
            a.severity = _first("severity", "s")
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
        "rule_add": cmd_rule_add,
        "rule_remove": cmd_rule_remove,
        "rule_test": cmd_rule_test,
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
                    "description": "Full security scan: decompile APK with jadx, then scan with 95+ regex patterns for leaked secrets (API keys, tokens, credentials, endpoints, private keys). Covers AWS, Azure, GCP, Alibaba, Tencent, DigitalOcean, OpenAI, Anthropic, Stripe, Shopify, GitHub, GitLab, SendGrid, Telegram, Cloudflare, Okta, and more. Results classified by severity (critical/high/medium/low/info). Takes 30-180 seconds.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "description": "Path to APK file"},
                            "severity": {"type": "string", "description": "Filter findings by minimum severity", "enum": ["critical", "high", "medium", "low", "info"]},
                            "pattern": {"type": "string", "description": "Path to custom patterns JSON file (uses default 95+ patterns if not set)"},
                            "jadx_args": {"type": "string", "description": "Extra jadx disassembler arguments (e.g. '--threads-count 5 --deobf')"},
                            "output": {"type": "string", "description": "Path to save results file (auto-generated if not set)"},
                            "json_output": {"type": "boolean", "description": "Save results in JSON format instead of text", "default": False},
                        },
                        "required": ["file"],
                    },
                },
                {
                    "name": "apkleaks_patterns",
                    "description": "List all 95+ regex detection pattern categories with severity levels. Covers cloud providers (AWS, Azure, GCP, Alibaba, Tencent, DigitalOcean), AI (OpenAI, Anthropic), messaging (SendGrid, Telegram, Twilio), payments (Stripe, Shopify, Square), DevOps (GitHub, GitLab, NPM), monitoring (Sentry, Datadog, NewRelic), and more. Use verbose=true to see pattern details.",
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
                {
                    "name": "apkleaks_rule_add",
                    "description": "Add a custom detection rule at runtime. Rules persist in-memory for the current session and are automatically merged into subsequent scans. Use this to extend APKLeaks with app-specific patterns (e.g. custom API endpoints, proprietary token formats).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Unique rule name (e.g. 'MyApp_API_Key'). Use snake_case."},
                            "regex": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}], "description": "Regex pattern(s). String for single, array for multi-pattern rules."},
                            "severity": {"type": "string", "description": "Severity level", "enum": ["critical", "high", "medium", "low", "info"], "default": "medium"},
                        },
                        "required": ["name", "regex"],
                    },
                },
                {
                    "name": "apkleaks_rule_remove",
                    "description": "Remove a custom detection rule previously added via rule_add. Built-in rules cannot be removed (use rule_add with the same name to override them).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Name of the custom rule to remove"},
                        },
                        "required": ["name"],
                    },
                },
                {
                    "name": "apkleaks_rule_test",
                    "description": "Test a regex pattern against sample text without scanning an APK. Validates the regex syntax and shows what it matches. Use this to validate rules before adding them via rule_add.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Rule name for reference (optional, defaults to 'test_rule')"},
                            "regex": {"type": "string", "description": "Regex pattern to test"},
                            "sample": {"type": "string", "description": "Sample text to test the regex against (optional)"},
                            "severity": {"type": "string", "description": "Severity level for the rule", "enum": ["critical", "high", "medium", "low", "info"], "default": "medium"},
                        },
                        "required": ["regex"],
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
                    "description": "All 95+ regex pattern definitions used by APKLeaks for secret scanning",
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
                {
                    "uri": "apkleaks:///source/",
                    "name": "Decompiled Source Files",
                    "description": "Read decompiled source files by absolute path. Use apkleaks:///source/{absolute_path} to read .java, .xml, .json, or .smali files from decompiled output.",
                    "mimeType": "text/plain",
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
                "apkleaks_rule_add": "rule_add",
                "apkleaks_rule_remove": "rule_remove",
                "apkleaks_rule_test": "rule_test",
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
    debug = getattr(args, "debug", False)
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
        if debug:
            print(f"[MCP] <- {json.dumps(request)[:200]}", file=sys.stderr)
        response = handle_request(request)
        if response is None:
            # Notification — no response required (e.g. notifications/initialized)
            continue
        if debug:
            print(f"[MCP] -> {json.dumps(response)[:200]}", file=sys.stderr)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


# ─── main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="apkleaks-ai-cli",
        description="APKLeaks AI-CLI — Structured JSON interface for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"apkleaks-ai-cli {VERSION}")
    parser.add_argument("--help-json", action="store_true",
                        help="Print tool schema as JSON and exit (for AI discovery)")
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
    p_scan.add_argument("-o", "--output", dest="output", default=None, help="Save results to file")
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

    # rule-add
    p_rule_add = subparsers.add_parser("rule-add", help="Add a custom detection rule at runtime")
    p_rule_add.add_argument("-n", "--name", dest="name", required=True,
                            help="Rule name (e.g. My_Custom_Key)")
    p_rule_add.add_argument("-r", "--regex", dest="regex", required=True,
                            help="Regex pattern string")
    p_rule_add.add_argument("-s", "--severity", dest="severity", default="medium",
                            choices=["critical", "high", "medium", "low", "info"],
                            help="Severity level (default: medium)")
    p_rule_add.set_defaults(func=cmd_rule_add)

    # rule-remove
    p_rule_remove = subparsers.add_parser("rule-remove", help="Remove a custom runtime rule")
    p_rule_remove.add_argument("-n", "--name", dest="name", required=True,
                               help="Rule name to remove")
    p_rule_remove.set_defaults(func=cmd_rule_remove)

    # rule-test
    p_rule_test = subparsers.add_parser("rule-test", help="Test a regex pattern against sample text")
    p_rule_test.add_argument("-r", "--regex", dest="regex", required=True,
                             help="Regex pattern to test")
    p_rule_test.add_argument("-t", "--text", dest="text", required=True,
                             help="Sample text to test against")
    p_rule_test.set_defaults(func=cmd_rule_test)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run as MCP server over stdio")
    p_mcp.add_argument("--debug", action="store_true", help="Log all MCP messages to stderr")
    p_mcp.set_defaults(func=cmd_mcp)

    args = parser.parse_args()

    # Handle --help-json: print schema as JSON and exit
    if args.help_json:
        result = cmd_schema(args)
        _write_json(result)
        sys.exit(0)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    result = args.func(args)
    if result is not None:
        _write_json(result)


if __name__ == "__main__":
    main()