---
name: rev-apkleaks
description: Activate when the user wants to scan an Android APK for secrets, API keys, tokens, endpoints, or sensitive information. Drives apkleaks-ai-cli.py via the Skills CLI (Bash) or the apkleaks MCP server. Returns severity-graded JSON findings.
---

# APKLeaks — Android APK Secret Scanner

**Announce:** "Using rev-apkleaks skill — APK security scanning mode engaged."

> This is the lean entry point. For the full surface — every subcommand flag, the
> complete MCP lifecycle, the resource/prompt catalog, and all error codes — read
> [`references/reference.md`](references/reference.md) in this skill directory when you need it.

## Pick a mode

| Mode | How | When |
|------|-----|------|
| **MCP** (preferred) | Call `apkleaks_*` tools directly | `.claude/settings.json` has `mcpServers.apkleaks` |
| **CLI** (always works) | `python3 apkleaks-ai-cli.py <sub>` via Bash | No MCP config / quick one-off |

**Auto-detect:** check `.claude/settings.json` for `mcpServers.apkleaks`. If present, prefer
MCP (no Bash subprocess). Otherwise use the CLI. Both expose the same engine and the same
JSON envelope, so the workflow below is identical either way.

## The contract (read this once)

Every call returns the same envelope. **Branch on `ok` first, then `error_code`** — never
parse prose to decide the next step.

```json
{ "ok": true,  "timestamp": "...", "duration_ms": 1234, "data": { /* result */ } }
{ "ok": false, "timestamp": "...", "error": "human text", "error_code": "FILE_NOT_FOUND" }
```

`error_code` can appear on success too (e.g. `NO_FINDINGS` with `ok:true`). `scan` data
carries `has_critical` and findings pre-sorted `critical → info`.

## Core workflow

Each step branches on the previous response:

```
schema                      → discover capabilities (once per session)
check  -f <apk>             → deps + APK valid?           branch on ok
info   -f <apk>             → package, SDK, permissions   (no decompile)
scan   -f <apk> -s high     → decompile + 95-pattern scan branch on has_critical
explain -c <category>       → impact + remediation        one per finding category
decompile + search          → pivot into source for proof (optional, on demand)
```

CLI form (MCP is the same call with `{file, severity, ...}` args):

```bash
python3 apkleaks-ai-cli.py schema
python3 apkleaks-ai-cli.py check  -f /path/app.apk
python3 apkleaks-ai-cli.py info   -f /path/app.apk
python3 apkleaks-ai-cli.py scan   -f /path/app.apk -s critical
python3 apkleaks-ai-cli.py explain -c Amazon_AWS_Access_Key_ID
# deep dive:
python3 apkleaks-ai-cli.py decompile -f /path/app.apk -o /tmp/app-src
python3 apkleaks-ai-cli.py search -d /tmp/app-src -p "password" -t java -c 2
```

`explain` takes partial / case-insensitive names, so pass a `scan` finding name straight in.

### What a finding looks like

```jsonc
// explain -c Anthropic_API_Key  (real output, trimmed)
{ "ok": true, "data": {
  "category": "Anthropic_API_Key", "severity": "critical",
  "description": "Anthropic API keys (sk-ant-api03- prefix) ... Revoke at console.anthropic.com.",
  "impact": "Immediate credential compromise. Rotate and revoke exposed secrets without delay.",
  "remediation": "Rotate the exposed credential immediately. Move secrets to a secrets manager. Audit access logs."
}}
```

## Custom rules (app-specific patterns)

Extend detection at runtime without touching files — validate, add, then scan:

```bash
python3 apkleaks-ai-cli.py rule-test -r 'myapp_[a-z0-9]{32}' -t 'token=myapp_0123456789abcdef0123456789abcdef'
python3 apkleaks-ai-cli.py rule-add  -n MyApp_Token -r 'myapp_[a-z0-9]{32}' -s high
```

Rules are **in-memory**: they persist for a live MCP session but reset between one-shot CLI
runs. See `references/reference.md` for the full lifecycle.

## Severity → action

| critical | high | medium | low | info |
|----------|------|--------|-----|------|
| rotate now | verify + restrict | check exploitability | note for report | no action |

Triage with `-s critical` (CLI) / `severity` (MCP) to keep only what matters and save tokens.

## Hard rules

1. **Branch on `ok`** — if false, read `error_code` before retrying.
2. **Never write found secrets to disk** — report in conversation only.
3. **Verify the APK first** — `check -f <apk>` before scanning.
4. **Clean up decompiled output** — remove temp dirs after analysis.
5. **Respect scope** — only scan APKs the user provides.
6. **Flag false positives** — mark test/placeholder values.
7. **Explain critical findings** — run `explain` for impact + remediation.
8. **Prefer MCP when configured** — direct tool calls over Bash.

## Chain with other skills

`/rev-dex-dumper` (class/method bytecode) · `/rev-frida` (runtime verification of static
hits) · `/rev-symbol` & `/rev-struct` (native libs). Use these to confirm or deepen findings.

---
**Need more?** Full subcommand flags, MCP lifecycle/resources/prompts, and the complete
error-code list live in [`references/reference.md`](references/reference.md).
