# APKLeaks
[![version](https://badge.fury.io/gh/dwisiswant0%2fapkleaks.svg)](https://badge.fury.io/gh/dwisiswant0%2fapkleaks.svg)
[![contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwisiswant0/apkleaks/issues)

Scanning APK file for URIs, endpoints & secrets.

<img src="https://user-images.githubusercontent.com/25837540/111927529-a4ade080-8ae3-11eb-800a-b764ab1242e1.jpg" alt="APKLeaks">

- [Installation](#installation)
  - [from Pypi](#from-pypi)
  - [from Source](#from-source)
  - [from Docker](#from-docker)
- [Usage](#usage)
  - [Options](#options)
    - [Output](#output)
    - [Pattern](#pattern)
    - [Arguments (for disassembler)](#arguments-for-disassembler)
- [AI Integration](#ai-integration)
  - [AI-CLI Subcommands](#ai-cli-subcommands)
  - [MCP Server (Claude Code)](#mcp-server-claude-code)
  - [MCP Runtime Options](#mcp-runtime-options)
- [License](#license)
- [Acknowledments](#acknowledments)

---

## Installation

It's fairly simple to install **APKLeaks**:

### from PyPi

```bash
$ pip3 install apkleaks
```

### from Source

Clone repository and install requirements:

```bash
$ git clone https://github.com/dwisiswant0/apkleaks
$ cd apkleaks/
$ pip3 install -r requirements.txt
```

### from Docker

Pull the Docker image by running:

```bash
$ docker pull dwisiswant0/apkleaks:latest
```

### Dependencies

The APKLeaks utilizes the [jadx](https://github.com/skylot/jadx) disassembler to decompile APK files. If jadx is not present in your system, it will prompt you to download it.

## Usage

Simply,

```bash
$ apkleaks -f ~/path/to/file.apk
# from Source
$ python3 apkleaks.py -f ~/path/to/file.apk
# or with Docker
$ docker run -it --rm -v /tmp:/tmp dwisiswant0/apkleaks:latest -f /tmp/file.apk
```

## Options

Here are all the options it supports.

| **Argument**  	| **Description**                             	| **Example**                                                   |
|---------------	|---------------------------------------------	|-------------------------------------------------------------  |
| -f, --file    	| APK file to scanning                        	| `apkleaks -f file.apk`                                        |
| -o, --output  	| Write to file results _(random if not set)_ 	| `apkleaks -f file.apk -o results.txt`                         |
| -p, --pattern 	| Path to custom patterns JSON                	| `apkleaks -f file.apk -p custom-rules.json`                   |
| -a, --args    	| Disassembler arguments                      	| `apkleaks -f file.apk --args="--deobf --log-level DEBUG"`     |
|     --json      | Save as JSON format                         	| `apkleaks -f file.apk -o results.json --json`                 |

### Output

In general, if you don't provide `-o` argument, then it will generate results file automatically.

> [!TIP]
> By default it will also save the results in text format, use `--json` argument if you want JSON output format.

### Pattern

Custom patterns can be added with the following argument to provide sensitive _search rules_ in the JSON file format: `--pattern /path/to/custom-rules.json`. If no file is set, the tool will use the default patterns found in [regexes.json](https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json) file.

Here's an example of what a custom pattern file could look like:

```json
// custom-rules.json
{
  "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
  // ...
}
```

To run the tool using these custom rules, use the following command:

```bash
$ apkleaks -f /path/to/file.apk -p rules.json -o ~/Documents/apkleaks-results.txt
```

### Arguments (disassembler)

We give user complete discretion to pass the disassembler arguments. For example, if you want to activate threads in `jadx` decompilation process, you can add it with `-a/--args` argument, example: `--args="--threads-count 5"`.

```
$ apkleaks -f /path/to/file.apk -a "--deobf --log-level DEBUG"
```

> [!WARNING]
> Please pay attention to the default disassembler arguments we use to prevent collisions.

## AI Integration

APKLeaks includes `apkleaks-ai-cli.py` — a structured JSON interface designed for AI agents (Claude Code, GPT, etc.) with 10 subcommands and an MCP server mode.

### AI-CLI Subcommands

| Subcommand | Description | Example |
|-----------|-------------|---------|
| `schema` | Tool self-description (AI discovers all capabilities) | `python3 apkleaks-ai-cli.py schema` |
| `version` | Show version info | `python3 apkleaks-ai-cli.py version` |
| `check` | Verify prerequisites + APK validity | `python3 apkleaks-ai-cli.py check -f app.apk` |
| `info` | Extract APK metadata (no decompile) | `python3 apkleaks-ai-cli.py info -f app.apk` |
| `scan` | Full scan: decompile + regex + severity | `python3 apkleaks-ai-cli.py scan -f app.apk` |
| `patterns` | List regex patterns with severity | `python3 apkleaks-ai-cli.py patterns -v` |
| `decompile` | Decompile APK to Java source | `python3 apkleaks-ai-cli.py decompile -f app.apk` |
| `search` | Search decompiled source with regex | `python3 apkleaks-ai-cli.py search -d /tmp/src -p "password"` |
| `explain` | Explain a finding category | `python3 apkleaks-ai-cli.py explain -c Amazon_AWS_Access_Key_ID` |
| `mcp` | Run as MCP server over stdio | `python3 apkleaks-ai-cli.py mcp` |

All subcommands return structured JSON:

```json
{"ok": true, "timestamp": "...", "duration_ms": 123, "data": {...}}
{"ok": false, "timestamp": "...", "error": "...", "error_code": "FILE_NOT_FOUND"}
```

### MCP Server (Claude Code)

The MCP server lets AI tools (like Claude Code) call APKLeaks directly without Bash subprocesses. It implements the [Model Context Protocol](https://modelcontextprotocol.io/) over stdio:

1. **Lifecycle:** `initialize` → `notifications/initialized` → ready
2. **Discovery:** `tools/list` returns 9 tool definitions with rich JSON Schema (descriptions, enums, defaults)
3. **Invocation:** `tools/call` dispatches `apkleaks_*` tool names to internal `cmd_*` functions
4. **Keep-alive:** `ping` responds immediately

The MCP server uses **lazy imports** — lifecycle methods (`initialize`, `ping`, `tools/list`) work without `pyaxmlparser` installed. Only actual scan/info/decompile calls require dependencies.

#### MCP Tools

| Tool Name | Description | Key Parameters |
|-----------|-------------|----------------|
| `apkleaks_schema` | Discover all capabilities | — |
| `apkleaks_version` | Version info | — |
| `apkleaks_check` | Verify prerequisites + APK validity | `file` |
| `apkleaks_info` | APK metadata (no decompile) | `file` |
| `apkleaks_scan` | Full scan with severity classification | `file`, `severity` (critical/high/medium/low/info), `pattern`, `jadx_args`, `output`, `json_output` |
| `apkleaks_patterns` | List regex detection patterns | `verbose` |
| `apkleaks_decompile` | Decompile to Java source | `file`, `output_dir`, `jadx_args` |
| `apkleaks_search` | Search decompiled source | `dir`, `pattern`, `type` (java/xml/json/smali/all), `context`, `limit` |
| `apkleaks_explain` | Explain a finding category | `category` |

### MCP Runtime Options

Choose a runtime based on your environment. All three are fully supported:

#### Option 1: `uv run` (Recommended)

Auto-installs dependencies into an isolated venv. No manual `pip install` needed.

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

Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

#### Option 2: `pipx run`

Similar to `uv run` — creates a temporary venv and installs deps. Good for non-uv users.

```json
{
  "mcpServers": {
    "apkleaks": {
      "command": "pipx",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}
```

Install pipx: `pip install pipx` or `brew install pipx`

#### Option 3: `python3` (Manual)

Direct execution. Requires `pip install -e .` or `pip install -r requirements.txt` first.

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

Add the config to your project's `.claude/settings.json` and Claude Code will automatically start the MCP server when you open the project.

## License

`apkleaks` is distributed under Apache 2.

## Acknowledments

Since this tool includes some contributions, and I'm not an asshole, I'll publically thank the following users for their helps and resources:

- [@ndelphit](https://github.com/ndelphit) - for his inspiring `apkurlgrep`, that's why this tool was made.
- [@dxa4481](https://github.com/dxa4481) and y'all who contribute to `truffleHogRegexes`.
- [@GerbenJavado](https://github.com/GerbenJavado) & [@Bankde](https://github.com/Bankde) - for awesome pattern to discover URLs, endpoints & their parameters from `LinkFinder`.
- [@tomnomnom](https://github.com/tomnomnom/gf) - a `gf` patterns.
- [@pxb1988](https://github.com/pxb1988) - for awesome APK dissambler `dex2jar`.
- [@subho007](https://github.com/ph4r05) for standalone APK parser.
- `SHA2048#4361` _(Discord user)_ that help me porting code to Python3.
- [@Ry0taK](https://github.com/Ry0taK) because he had reported an [OS command injection bug](https://github.com/dwisiswant0/apkleaks/security/advisories/GHSA-8434-v7xw-8m9x).
- [@dee__see](https://twitter.com/dee__see) - for curated potentially sensitive tokens, `NotKeyHacks`.
- [All contributors](https://github.com/dwisiswant0/apkleaks/graphs/contributors).
