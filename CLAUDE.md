# APKLeaks Project — AI-Assisted Reverse Engineering

## Project Overview

APKLeaks (v2.6.3) is an Android APK security scanning tool that decompiles APK files using jadx and scans for sensitive information (API keys, tokens, credentials, endpoints, private keys) via 60+ regex patterns.

## Dual Integration Mode

APKLeaks supports **two ways** for AI to interact with the tool:

| Mode | Entry Point | Setup |
|------|------------|-------|
| **Skills CLI** | `python3 apkleaks-ai-cli.py <subcommand>` | No setup needed — works via Bash tool |
| **MCP Server** | `.claude/settings.json` mcpServers config | Claude Code calls tools directly |

When MCP is configured (default in this project), AI can call `apkleaks` tools natively without Bash subprocess.

## Key Files

- `apkleaks.py` — Top-level CLI entry point (original)
- `apkleaks-ai-cli.py` — AI-CLI with 10 subcommands (schema, version, check, info, scan, patterns, decompile, search, explain, mcp)
- `apkleaks/cli.py` — CLI argument parsing and pipeline orchestration
- `apkleaks/apkleaks.py` — Core APKLeaks class (integrity check, decompile, scan, extract, cleanup)
- `apkleaks/utils.py` — File walker + regex finder
- `apkleaks/colors.py` — ANSI color codes
- `config/regexes.json` — 60+ regex pattern definitions
- `.claude/settings.json` — MCP server configuration for Claude Code

## Skills Available

| Skill | Command | Purpose |
|-------|---------|---------|
| **rev-apkleaks** | `/rev-apkleaks` | Scan APK for secrets, endpoints, credentials (CLI + MCP) |
| **rev-dex-dumper** | `/rev-dex-dumper` | DEX file disassembly and analysis |
| **rev-frida** | `/rev-frida` | Dynamic instrumentation and runtime hooking |
| **rev-idapython** | `/rev-idapython` | IDA Pro Python scripting |
| **rev-ios-dump** | `/rev-ios-dump` | iOS app dumping and analysis |
| **rev-struct** | `/rev-struct` | Data structure reconstruction from binary analysis |
| **rev-symbol** | `/rev-symbol` | Symbol table analysis and recovery |
| **rev-u3d-dump** | `/rev-u3d-dump` | Unity3D asset extraction |
| **rev-unicorn-debug** | `/rev-unicorn-debug` | CPU emulation and debugging |

## AI-CLI Subcommands

| Subcommand | Purpose | AI-Friendly Feature |
|-----------|---------|-------------------|
| `schema` | Tool self-description | AI discovers all capabilities in one call |
| `version` | Version info | Confirm tool version |
| `check` | Verify prerequisites | Structured error codes |
| `info` | APK metadata | Permission auto-categorization |
| `scan` | Full scan + severity | Results sorted critical→info, has_critical flag |
| `patterns` | Regex patterns + severity | Priority-aware listing |
| `decompile` | Decompile to Java source | Returns file count + duration |
| `search` | Search decompiled source | File type filter + context lines |
| `explain` | Explain finding category | Impact + remediation guidance |
| `mcp` | MCP server over stdio | Direct AI tool integration |

## MCP Server

The MCP server (`apkleaks-ai-cli.py mcp`) implements the MCP specification with full capabilities:

- **Lifecycle:** `initialize` → `notifications/initialized` → ready
- **Tools:** `tools/list` returns 9 tools with rich JSON Schema; `tools/call` returns MCP CallToolResult
- **Resources:** `resources/list` exposes config files; `resources/read` reads regexes, severity map, explanations, and decompiled source files
- **Prompts:** `prompts/list` returns 4 analysis templates; `prompts/get` returns parameterized prompt messages
- **Logging:** `logging/setLevel` accepted (no-op, logs already silenced)
- **Keep-alive:** `ping` responds immediately
- **Lazy imports:** Lifecycle methods work without pyaxmlparser; only scan/info/decompile require it

### MCP Tools

| Tool Name | Description | Key Parameters |
|-----------|-------------|----------------|
| `apkleaks_schema` | Discover all capabilities | — |
| `apkleaks_version` | Version info | — |
| `apkleaks_check` | Verify prerequisites + APK validity | `file` |
| `apkleaks_info` | APK metadata (no decompile) | `file` |
| `apkleaks_scan` | Full scan with severity | `file`, `severity` (critical/high/medium/low/info), `pattern`, `jadx_args`, `output`, `json_output` |
| `apkleaks_patterns` | List regex patterns | `verbose` |
| `apkleaks_decompile` | Decompile to Java source | `file`, `output_dir`, `jadx_args` |
| `apkleaks_search` | Search decompiled source | `dir`, `pattern`, `type` (java/xml/json/smali/all), `context`, `limit` |
| `apkleaks_explain` | Explain finding category | `category` |

### MCP Resources

| URI | Description | MIME Type |
|-----|-------------|-----------|
| `apkleaks:///config/regexes` | All 60+ regex pattern definitions | application/json |
| `apkleaks:///config/severity-map` | Category → severity mapping | application/json |
| `apkleaks:///config/explanations` | Finding explanations (impact + remediation) | application/json |
| `apkleaks:///source/{path}` | Read any decompiled source file (dynamic) | auto-detected |

### MCP Prompts

| Name | Description | Arguments |
|------|-------------|-----------|
| `security-audit` | Full security audit with remediation | `apk_path`, `severity_filter` |
| `credential-rotation` | Credential rotation plan | `apk_path` |
| `api-inventory` | API endpoint catalog | `apk_path` |
| `permission-risk` | Permission risk assessment | `apk_path` |

### MCP Runtime Options

The MCP server can be launched with different Python runtimes. Choose based on your environment:

| Runtime | Config | Pros | Cons |
|---------|--------|------|------|
| **uv run** (recommended) | `"command": "uv", "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]` | Auto-installs deps into isolated venv; no manual pip install | Requires uv installed |
| **python3** (fallback) | `"command": "python3", "args": ["apkleaks-ai-cli.py", "mcp"]` | No extra tool needed | Requires manual `pip install -e .` first |
| **pipx run** | `"command": "pipx", "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]` | Auto-installs deps; good for non-uv users | Slower than uv |

Default configuration in `.claude/settings.json` uses `uv run`:
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

If you don't have uv, install it: `curl -LsSf https://astral.sh/uv/install.sh | sh`
Or switch to python3 fallback: change `"command"` to `"python3"` and `"args"` to `["apkleaks-ai-cli.py", "mcp"]` (after `pip install -e .`).

## Tech Stack

- Python >= 3.8
- jadx v1.2.0 (auto-downloaded)
- pyaxmlparser >= 0.3.24

## Conventions

- CLI args: `-f` (APK file), `-o` (output), `-p` (custom patterns), `-a` (jadx args), `--json`
- Regex patterns defined in `config/regexes.json` as key-value pairs
- Output formats: plain text (default) or JSON (`--json` flag)
- Each regex pattern runs in its own thread during scanning
- AI-CLI responses: `{"ok": bool, "timestamp": "...", "data": {...}, "error_code": "..."}`

## Workflow Tips

- Start with `/rev-apkleaks` for quick secret scanning
- Use `schema` subcommand to discover all capabilities
- Use `scan -s critical` to focus on high-severity findings first
- Use `explain -c <category>` to understand impact and remediation
- Use `/rev-dex-dumper` for deeper class/method analysis
- Use `/rev-frida` for runtime verification of static findings
- Use `/rev-struct` and `/rev-symbol` for native library analysis
