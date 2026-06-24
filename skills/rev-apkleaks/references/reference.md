# rev-apkleaks — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full surface: every subcommand flag, the complete MCP lifecycle, the
> resource/prompt catalog, and the full error-code list.

## Full AI-CLI subcommand reference (13)

`python3 apkleaks-ai-cli.py <subcommand>` — every call prints the JSON envelope on stdout.

| Subcommand | Purpose | Flags | Notes |
|-----------|---------|-------|-------|
| `schema` | Self-describing tool definition | — | Returns every subcommand, severity map summary, error codes. Call once per session. |
| `version` | Tool + Python version | — | |
| `check` | Verify prerequisites (+ optional APK) | `-f <apk>` | `ok:false` if any dep missing; inspect per-key `ok`. APK arg optional. |
| `info` | APK metadata, no decompile | `-f <apk>` | Package, SDK levels, activities/services/receivers/providers, `permission_summary` (auto-categorized). Needs `pyaxmlparser`. |
| `scan` | Decompile + regex + severity | `-f <apk>` `-s <sev>` `-p <file>` `-a <jadx>` `-o <out>` | `-s` filters to that severity **and above**. `-p` = custom patterns JSON (overrides runtime rules). `data.has_critical` for fast triage. |
| `patterns` | List detection categories | `-p <file>` `-v` | `-v` includes the raw regex(es). `is_custom` flags runtime-added rules. |
| `decompile` | jadx → Java source | `-f <apk>` `-o <dir>` `-a <jadx>` | Auto temp dir if `-o` omitted; returns `output_dir` + `file_count`. 600s timeout. |
| `search` | Regex over decompiled source | `-d <dir>` `-p <regex>` `-t <type>` `-c <ctx>` `-l <limit>` | `-t` ∈ java/xml/json/smali/all. `-c` = context lines. Case-insensitive, multiline. CLI `-l` default 500. |
| `explain` | Category impact + remediation | `-c <category>` | Partial / case-insensitive match — pass a `scan` finding name directly. |
| `rule-add` | Add runtime detection rule | `-n <name>` `-r <regex>` `-s <sev>` | In-memory only; persists within one process (a live MCP session). Same name as a built-in → override. |
| `rule-remove` | Remove a runtime rule | `-n <name>` | Built-ins can't be removed (override instead). |
| `rule-test` | Validate a regex vs sample | `-r <regex>` `-t <text>` | Reports validity + matches before you commit a rule. |
| `mcp` | MCP server over stdio | `--debug` | JSON-RPC on stdin/stdout. |

### Runtime-rule lifecycle (one-shot CLI vs MCP)

`rule-add` / `rule-remove` mutate an **in-memory** ruleset. Across separate one-shot CLI
invocations the ruleset resets to defaults every time. Inside a single long-running **MCP
session** the rules persist and are auto-merged into every subsequent `scan` until removed.
Use `rule-test` first to validate, then `rule-add`, then `scan`.

## MCP setup (3 runtimes)

Drop one into `.claude/settings.json`; Claude Code starts the server when the project opens.

```json
// Option 1 — uv run (recommended; auto-installs deps into an isolated venv)
{ "mcpServers": { "apkleaks": {
  "command": "uv",
  "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"] } } }

// Option 2 — pipx run (auto-installs; for non-uv users)
{ "mcpServers": { "apkleaks": {
  "command": "pipx",
  "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"] } } }

// Option 3 — python3 (manual; requires `pip install -e .` first)
{ "mcpServers": { "apkleaks": {
  "command": "python3",
  "args": ["apkleaks-ai-cli.py", "mcp"] } } }
```

Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

## MCP tools (12) with example arguments

| Tool | Example call |
|------|--------------|
| `apkleaks_schema` | `{}` |
| `apkleaks_version` | `{}` |
| `apkleaks_check` | `{ "file": "/path/app.apk" }` |
| `apkleaks_info` | `{ "file": "/path/app.apk" }` |
| `apkleaks_scan` | `{ "file": "/path/app.apk", "severity": "critical" }` |
| `apkleaks_patterns` | `{ "verbose": true }` |
| `apkleaks_decompile` | `{ "file": "/path/app.apk", "output_dir": "/tmp/src" }` |
| `apkleaks_search` | `{ "dir": "/tmp/src", "pattern": "password", "type": "java", "context": 2 }` |
| `apkleaks_explain` | `{ "category": "Amazon_AWS_Access_Key_ID" }` |
| `apkleaks_rule_add` | `{ "name": "MyApp_Token", "regex": "tok_[0-9a-f]{32}", "severity": "high" }` |
| `apkleaks_rule_remove` | `{ "name": "MyApp_Token" }` |
| `apkleaks_rule_test` | `{ "regex": "tok_[0-9a-f]{32}", "sample": "tok_0123...", "severity": "high" }` |

## MCP lifecycle (10 methods)

1. `initialize` → protocol version + capabilities (tools, resources, prompts, logging)
2. `notifications/initialized` → client confirms ready (no response)
3. `tools/list` → 12 tool definitions with rich JSON Schema
4. `tools/call` → dispatches `apkleaks_*`; returns MCP `CallToolResult`
5. `resources/list` → 3 static config resources + 1 dynamic source reader
6. `resources/read` → reads config or decompiled source by URI
7. `prompts/list` → 4 analysis templates
8. `prompts/get` → parameterized prompt messages
9. `logging/setLevel` → accepted (no-op; logs already silenced)
10. `ping` → keep-alive

**Lazy imports:** `initialize` / `ping` / `tools/list` work even without `pyaxmlparser`.
Only `scan` / `info` / `decompile` need the heavy deps.

## MCP resources

| URI | Description | MIME |
|-----|-------------|------|
| `apkleaks:///config/regexes` | All 95 regex pattern definitions | application/json |
| `apkleaks:///config/severity-map` | Category → severity mapping | application/json |
| `apkleaks:///config/explanations` | Per-category impact + remediation | application/json |
| `apkleaks:///source/{absolute_path}` | Read a decompiled source file (dynamic) | auto-detected |

## MCP prompts

| Name | Description | Arguments |
|------|-------------|-----------|
| `security-audit` | Full audit with remediation | `apk_path`, `severity_filter` |
| `credential-rotation` | Credential rotation plan | `apk_path` |
| `api-inventory` | API endpoint catalog | `apk_path` |
| `permission-risk` | Permission risk assessment | `apk_path` |

## Response format

`tools/call` returns the MCP `CallToolResult`:
- `content`: `[{ "type": "text", "text": "<JSON string>" }]`
- `isError`: `true` when the inner JSON has `ok: false`

Inner JSON (identical to the CLI envelope):
- Success: `{ "ok": true, "timestamp": "...", "duration_ms": N, "data": { ... } }`
- Error: `{ "ok": false, "timestamp": "...", "error": "...", "error_code": "FILE_NOT_FOUND" }`

`error_code` may also appear on a **success** response (e.g. `NO_FINDINGS` when a scan
completes cleanly with zero hits) — branch on `ok` first, then read `error_code`.

## Error codes

| Code | Meaning |
|------|---------|
| `FILE_NOT_FOUND` | APK / path does not exist |
| `INVALID_APK` | Exists but not a valid Android APK |
| `JADX_NOT_FOUND` | jadx binary unavailable (run `check`) |
| `JADX_FAILED` | jadx decompilation failed |
| `JADX_TIMEOUT` | jadx exceeded the 600s limit |
| `INVALID_REGEX` | Bad regex in `search` / `rule-add` / `rule-test` |
| `DIR_NOT_FOUND` | `search` directory missing |
| `PATTERN_FILE_NOT_FOUND` | Custom `-p` patterns file missing |
| `UNKNOWN_CATEGORY` | `explain` category not recognized |
| `NO_FINDINGS` | Scan succeeded, zero secrets (appears with `ok:true`) |
| `SCAN_FAILED` | Scanning process errored |
| `MISSING_ARG` | Required argument not supplied |

## Severity classification

| Severity | Examples | Action |
|----------|----------|--------|
| **critical** | AWS/Stripe/Anthropic keys, private keys, keystore passwords | Rotate immediately |
| **high** | OAuth tokens, Firebase, GitHub PATs, Sentry DSN | Verify and restrict |
| **medium** | Generic API keys, URLs (LinkFinder), Stripe public keys | Check exploitability |
| **low** | IP / MAC addresses, mailto | Note for report |
| **info** | CTF flags | No action |

## Detection coverage

95 pattern categories across 12 themes: cloud providers (AWS, Azure, GCP, Alibaba,
Tencent, DigitalOcean) · AI/LLM (OpenAI, Anthropic) · messaging (SendGrid, Telegram,
Twilio, Slack) · payments (Stripe, Shopify, Square, PayPal) · DevOps/CI (GitHub, GitLab,
NPM, NuGet, Buildkite) · monitoring (Sentry, Datadog, New Relic) · CDN/edge (Cloudflare,
Fastly) · hosting (Vercel, Netlify, Heroku) · identity (Okta) · private keys (RSA, PGP,
SSH) · Android-specific (keystore passwords) · generic (tokens, passwords, JWT).

Read the live set via `patterns` / `apkleaks_patterns` or the
`apkleaks:///config/regexes` resource; extend at runtime with `rule-add`.
