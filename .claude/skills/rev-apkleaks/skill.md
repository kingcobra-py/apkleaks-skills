---
name: rev-apkleaks
description: Activate when the user wants to scan an Android APK for secrets, API keys, tokens, endpoints, or sensitive information. Uses apkleaks-ai-cli.py — supports both Skills CLI invocation and MCP Server mode.
autoInvoke: false
---

# APKLeaks — Android APK Secret Scanner (Dual Mode)

**Announce:** "Using rev-apkleaks skill — APK security scanning mode engaged."

## Two Ways to Use

This skill supports **two invocation modes**:

| Mode | How | When |
|------|-----|------|
| **Skills CLI** | `python3 apkleaks-ai-cli.py <subcommand>` via Bash tool | Default — always works, no setup needed |
| **MCP Server** | Claude Code calls `apkleaks` MCP tools directly | When `.claude/settings.json` has MCP config — AI calls tools without Bash |

**Auto-detection:** If MCP server is configured (check `.claude/settings.json` for `mcpServers.apkleaks`), prefer MCP mode for direct tool calls. Otherwise, use CLI mode via Bash.

## AI-CLI Subcommands (10 total)

| Subcommand | Purpose | Key Flags |
|-----------|---------|-----------|
| `schema` | Self-describing tool definition for AI discovery | (none) |
| `version` | Show tool version | (none) |
| `check` | Verify prerequisites + APK validity | `-f <apk>` (optional) |
| `info` | Extract APK metadata (no decompile) | `-f <apk>` |
| `scan` | Full scan: decompile + regex + severity | `-f <apk>`, `-s <severity>`, `-p`, `-a` |
| `patterns` | List regex patterns with severity | `-v` (verbose) |
| `decompile` | Decompile APK to Java source | `-f <apk>`, `-o <dir>`, `-a` |
| `search` | Search decompiled source with regex | `-d <dir>`, `-p <regex>`, `-t <type>`, `-c <ctx>` |
| `explain` | Explain a finding category | `-c <category>` |
| `mcp` | Run as MCP server over stdio | (none) |

## Execution Flow

```
Step 0: Discover capabilities
  → CLI: python3 apkleaks-ai-cli.py schema
  → MCP: call apkleaks schema tool directly

Step 1: Check prerequisites
  → CLI: python3 apkleaks-ai-cli.py check -f <apk>
  → MCP: call apkleaks check with {file: "<apk>"}

Step 2: Get APK info
  → CLI: python3 apkleaks-ai-cli.py info -f <apk>
  → MCP: call apkleaks info with {file: "<apk>"}

Step 3: Run full scan with severity
  → CLI: python3 apkleaks-ai-cli.py scan -f <apk>
  → MCP: call apkleaks scan with {file: "<apk>"}
  → Results sorted: critical → high → medium → low → info

Step 4: Explain findings
  → CLI: python3 apkleaks-ai-cli.py explain -c <category>
  → MCP: call apkleaks explain with {category: "<name>"}

Step 5: (Optional) Deep search
  → CLI: python3 apkleaks-ai-cli.py decompile + search
  → MCP: call apkleaks decompile + search sequentially
```

## CLI Mode Commands

```bash
# Discover capabilities
python3 apkleaks-ai-cli.py schema

# Check prerequisites
python3 apkleaks-ai-cli.py check -f /path/to/app.apk

# Get APK metadata
python3 apkleaks-ai-cli.py info -f /path/to/app.apk

# Full scan with severity
python3 apkleaks-ai-cli.py scan -f /path/to/app.apk
python3 apkleaks-ai-cli.py scan -f /path/to/app.apk -s critical

# List patterns
python3 apkleaks-ai-cli.py patterns -v

# Decompile + search
python3 apkleaks-ai-cli.py decompile -f /path/to/app.apk -o /tmp/app-src
python3 apkleaks-ai-cli.py search -d /tmp/app-src -p "password" -t java -c 2

# Explain findings
python3 apkleaks-ai-cli.py explain -c Amazon_AWS_Access_Key_ID
```

## MCP Mode Setup

To enable MCP mode, the project includes `.claude/settings.json` with:

**Recommended (uv run — auto-installs deps):**
```json
{
  "mcpServers": {
    "apkleaks": {
      "command": "uv",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}
```

**Fallback (python3 — requires manual `pip install -e .`):**
```json
{
  "mcpServers": {
    "apkleaks": {
      "command": "python3",
      "args": ["apkleaks-ai-cli.py", "mcp"]
    }
  }
}
```

When MCP is active, Claude Code can call `apkleaks_*` tools directly:
- `apkleaks_schema` — discover all capabilities
- `apkleaks_check` — with `{file: "/path/to/app.apk"}`
- `apkleaks_scan` — with `{file: "/path/to/app.apk", severity: "critical"}`
- `apkleaks_info` — with `{file: "/path/to/app.apk"}`
- `apkleaks_patterns` — with `{verbose: true}`
- `apkleaks_decompile` — with `{file: "/path/to/app.apk"}`
- `apkleaks_search` — with `{dir: "/tmp/src", pattern: "password"}`
- `apkleaks_explain` — with `{category: "Amazon_AWS_Access_Key_ID"}`
- `apkleaks_version` — no args needed

## MCP Lifecycle

The MCP server implements the standard lifecycle with full capabilities:
1. `initialize` — Returns protocol version + capabilities (tools, resources, prompts, logging)
2. `notifications/initialized` — Client confirms ready
3. `tools/list` — Returns 9 tool definitions with rich JSON Schema
4. `tools/call` — Dispatches `apkleaks_*` tool names; returns MCP CallToolResult format
5. `resources/list` — Returns 3 static + dynamic source resources
6. `resources/read` — Reads config files or decompiled source by URI
7. `prompts/list` — Returns 4 analysis templates
8. `prompts/get` — Returns parameterized prompt messages
9. `logging/setLevel` — Accepted (no-op)
10. `ping` — Keep-alive

The MCP server uses lazy imports — lifecycle methods work without pyaxmlparser installed. Only scan/info/decompile calls require dependencies.

## MCP Resources

| URI | Description |
|-----|-------------|
| `apkleaks:///config/regexes` | All 60+ regex pattern definitions |
| `apkleaks:///config/severity-map` | Category → severity mapping |
| `apkleaks:///config/explanations` | Finding explanations (impact + remediation) |
| `apkleaks:///source/{path}` | Read decompiled source file (dynamic) |

## MCP Prompts

| Name | Description | Arguments |
|------|-------------|-----------|
| `security-audit` | Full security audit with remediation | `apk_path`, `severity_filter` |
| `credential-rotation` | Credential rotation plan | `apk_path` |
| `api-inventory` | API endpoint catalog | `apk_path` |
| `permission-risk` | Permission risk assessment | `apk_path` |

## Response Format

All `tools/call` returns follow MCP CallToolResult:
- `content`: `[{"type": "text", "text": "<JSON string>"}]`
- `isError`: `true` if `ok: false` in the inner JSON

Inner JSON format:
- Success: `{"ok": true, "timestamp": "...", "duration_ms": N, "data": {...}}`
- Error: `{"ok": false, "timestamp": "...", "error": "...", "error_code": "FILE_NOT_FOUND"}`

## Error Codes

| Code | Meaning |
|------|---------|
| `FILE_NOT_FOUND` | APK file does not exist |
| `INVALID_APK` | Not a valid Android APK |
| `JADX_NOT_FOUND` | jadx binary not available |
| `JADX_FAILED` | jadx decompilation failed |
| `JADX_TIMEOUT` | jadx exceeded time limit |
| `INVALID_REGEX` | Bad regex pattern |
| `SCAN_FAILED` | Scanning error |

## Severity Classification

| Severity | Examples | Action |
|----------|----------|--------|
| **Critical** | AWS keys, Stripe keys, private keys | Immediate rotation |
| **High** | OAuth tokens, Firebase URLs | Verify and restrict |
| **Medium** | Generic API keys, URLs | Check exploitability |
| **Low** | IP/MAC addresses, emails | Note for report |
| **Info** | CTF flags | No action |

## Typical AI Workflow

1. **New session:** `schema` → Learn available commands
2. **Validate:** `check -f <apk>` → Confirm environment
3. **Recon:** `info -f <apk>` → Attack surface overview
4. **Scan:** `scan -f <apk>` → Findings by severity
5. **Explain:** `explain -c <category>` → Impact + remediation
6. **Deep dive:** `decompile` + `search` → Targeted analysis
7. **Cross-ref:** `/rev-dex-dumper`, `/rev-frida`, `/rev-symbol`

## Hard Rules

1. **Always check response `ok` field** — If false, read `error_code`
2. **Never store found secrets in files** — Report in conversation only
3. **Always verify APK exists** — Use `check -f <apk>` first
4. **Clean up decompiled directories** — Remove after analysis
5. **Respect scope** — Only scan APKs the user provides
6. **Flag false positives** — Mark test/placeholder values
7. **Explain critical findings** — Use `explain` for impact
8. **Prefer MCP mode when available** — Direct tool calls over Bash subprocess