# APKLeaks 项目 Skills 创建计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 APKLeaks CLI 工具封装为 Claude Code Skill，并填充 8 个逆向工程 Skill 定义文件，使项目具备完整的 AI 辅助逆向工程能力。

**Architecture:** 用户通过 `/rev-apkleaks` 调用 APKLeaks 扫描 → AI 读取 skill.md 获取指令 → 执行 jadx 反编译 + 正则扫描 → 返回结果。8 个 rev-* Skills 各自封装对应工具的调用流程。数据流：用户输入 APK 路径 → Skill 指令注入 → AI 调用 CLI/Bash → 解析输出 → 格式化返回。

**Tech Stack:** Python 3.8+, jadx 1.2.0, pyaxmlparser 0.3.24, Claude Code Skills (YAML frontmatter + Markdown)

**Scope:** Medium

**Risk:** Low

**Risks:**
- Skill 定义文件格式需与 Claude Code 兼容 → 缓解：使用已验证的 frontmatter 格式（name + description + autoInvoke）
- 项目级 `.claude/` 目录不存在 → 缓解：Task 1 先创建目录结构
- jadx 和依赖工具可能未安装 → 缓解：Skill 中包含依赖检查和自动安装步骤

**Autonomy Level:** Full

---

### Task 1: 创建 rev-apkleaks Skill — 封装 APKLeaks CLI 为可调用 Skill

**Depends on:** None
**Files:**
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-apkleaks/skill.md`

- [ ] **Step 1: 创建 .claude/skills 目录结构**

创建项目级 `.claude/skills/` 目录，确保路径存在。

- [ ] **Step 2: 创建 rev-apkleaks skill.md — 封装 APKLeaks CLI 扫描能力**

```markdown
---
name: rev-apkleaks
description: Activate when the user wants to scan an Android APK for secrets, API keys, tokens, endpoints, or sensitive information. Use when the user provides an APK file and wants to extract URIs, credentials, or perform security audit on the APK. Wraps the apkleaks CLI tool (jadx decompile + regex pattern matching).
autoInvoke: false
---

# APKLeaks — Android APK Secret Scanner

**Announce:** "Using rev-apkleaks skill — APK security scanning mode engaged."

## Overview

APKLeaks decompiles Android APK files using jadx and scans the decompiled source for sensitive information: API keys, tokens, credentials, private keys, endpoints, and CTF flags.

## Prerequisites Check

Before running any scan, verify:

1. **Python 3.8+** — Run `python3 --version`
2. **APKLeaks installed** — Run `python3 -c "import apkleaks"` or check if `apkleaks` CLI is available
   - If not installed: `pip3 install apkleaks`
3. **jadx available** — Run `which jadx` or check `jadx/bin/jadx`
   - If not available: APKLeaks will auto-download jadx v1.2.0 on first run
4. **APK file exists** — Verify the provided APK path is valid

## Execution Flow

```
User provides APK path
      ↓
Prerequisites check (Python + apkleaks + jadx + APK)
      ↓
Run apkleaks scan
      ↓
Parse and format results
      ↓
Present findings to user
```

## Scan Commands

### Basic Scan
```bash
python3 apkleaks.py -f <apk_path>
```

### Scan with Output File
```bash
python3 apkleaks.py -f <apk_path> -o <output_path>
```

### Scan with JSON Output
```bash
python3 apkleaks.py -f <apk_path> --json
```

### Scan with Custom Regex Patterns
```bash
python3 apkleaks.py -f <apk_path> -p <custom_patterns.json>
```

### Scan with Extra jadx Arguments
```bash
python3 apkleaks.py -f <apk_path> -a "--no-res"
```

### Docker Scan
```bash
docker run -it --rm -v /tmp:/tmp dwisiswant0/apkleaks -f /tmp/<apk_name>
```

## Result Interpretation

After scanning, categorize findings by severity:

| Category | Examples | Severity |
|----------|----------|----------|
| **Cloud Credentials** | AWS Access Key, Google API Key, Firebase URL | Critical |
| **Auth Tokens** | JWT, OAuth Token, Bearer Token | Critical |
| **Private Keys** | RSA, SSH, PGP Private Key | Critical |
| **Payment Keys** | Stripe, Square, PayPal Braintree | Critical |
| **Social Tokens** | Facebook, Twitter, Slack, Discord | High |
| **API Endpoints** | Internal URLs, REST endpoints | Medium |
| **Generic Secrets** | Generic API Key, password in URL | Medium |
| **CTF Flags** | DEFCON, HackerOne, HackTheBox | Info |

## Post-Scan Actions

After presenting results, suggest:

1. **Verify findings** — Confirm secrets are not false positives (test values, placeholders)
2. **Assess impact** — Which secrets are actively exploitable?
3. **Deep analysis** — For interesting findings, use `/rev-dex-dumper` to examine specific classes
4. **Frida hooking** — For runtime secrets, use `/rev-frida` to intercept dynamic values
5. **Custom patterns** — If standard patterns miss something, create custom regex file and re-scan

## Hard Rules

1. **Never store found secrets in plain text files** — Report findings in conversation only
2. **Always verify APK file exists before scanning** — Prevent wasted jadx decompile time
3. **Always clean up temp files** — APKLeaks auto-cleans, but verify if interrupted
4. **Respect scope** — Only scan APKs the user explicitly provides
5. **Report false positive indicators** — Flag likely test/placeholder values (e.g., "YOUR_API_KEY_HERE")
```

- [ ] **Step 3: 验证 skill.md 文件已创建**
Run: `ls -la /data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-apkleaks/skill.md`
Expected:
  - Exit code: 0
  - Output contains: "skill.md"

- [ ] **Step 4: 提交**
Run: `git add .claude/skills/rev-apkleaks/skill.md && git commit -m "feat(skills): add rev-apkleaks skill — APKLeaks CLI wrapper for APK secret scanning"`

---

### Task 2: 创建 8 个逆向工程 Skill 定义文件

**Depends on:** Task 1
**Files:**
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-dex-dumper/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-frida/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-idapython/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-ios-dump/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-struct/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-symbol/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-u3d-dump/skill.md`
- Create: `/data/local/tmp/workspace/github/AI-apkleaks/.claude/skills/rev-unicorn-debug/skill.md`

- [ ] **Step 1: 创建 rev-dex-dumper skill.md — DEX 文件转储与分析**

```markdown
---
name: rev-dex-dumper
description: Activate when the user wants to dump, disassemble, or analyze DEX files from an Android APK. Use when extracting class definitions, method signatures, or bytecode from DEX files. Works with dexdump, baksmali, or similar DEX analysis tools.
autoInvoke: false
---

# DEX Dumper — Android DEX File Analysis

**Announce:** "Using rev-dex-dumper skill — DEX disassembly mode engaged."

## Overview

Dump and analyze DEX (Dalvik Executable) files from Android APKs. Extract class definitions, method signatures, field references, and bytecode for reverse engineering.

## Prerequisites

1. **dexdump** (Android SDK build-tools) — `dexdump` or `$ANDROID_HOME/build-tools/<version>/dexdump`
2. **baksmali** — `baksmali --version` (for Smali disassembly)
3. **apktool** — `apktool --version` (for APK unpacking)

## Execution Flow

```
User provides APK/DEX path
      ↓
Unpack APK if needed (apktool d)
      ↓
Identify DEX files (classes.dex, classes2.dex, ...)
      ↓
Run dexdump/baksmali on target DEX
      ↓
Parse and present class/method/field info
```

## Commands

### List All Classes
```bash
dexdump -l plain <file>.dex | grep "Class descriptor"
```

### Disassemble to Smali
```bash
baksmali d <file>.dex -o <output_dir>
```

### Full DEX Dump
```bash
dexdump -d -f <file>.dex
```

### Unpack APK First
```bash
apktool d <file>.apk -o <output_dir>
```

## Analysis Targets

| Target | Command Pattern | Output |
|--------|----------------|--------|
| Class list | `dexdump -l plain` | All class descriptors |
| Method signatures | `dexdump -d` | Method names + signatures |
| String table | `dexdump -f` | All string constants |
| Smali code | `baksmali d` | Disassembled bytecode |
| Field references | `dexdump -d` | Static/instance fields |

## Post-Analysis

1. **Interesting classes** — Look for auth, crypto, network, config classes
2. **Hardcoded strings** — Check string table for URLs, keys, paths
3. **Native methods** — Flag methods declared `native` for further analysis
4. **Cross-reference** — Use `/rev-symbol` to trace symbol references

## Hard Rules

1. Always verify DEX file exists before dumping
2. Output can be very large — use grep/filter for targeted analysis
3. Clean up unpacked APK directories after analysis
```

- [ ] **Step 2: 创建 rev-frida skill.md — Frida 动态插桩**

```markdown
---
name: rev-frida
description: Activate when the user wants to dynamically instrument, hook, or trace functions in a running application using Frida. Use for runtime API interception, SSL pinning bypass, root detection bypass, or dynamic analysis of Android/iOS apps.
autoInvoke: false
---

# Frida — Dynamic Instrumentation Toolkit

**Announce:** "Using rev-frida skill — dynamic instrumentation mode engaged."

## Overview

Frida enables runtime function hooking, method tracing, and dynamic analysis of running applications. Inject JavaScript snippets into native functions or Java methods to intercept, modify, or observe behavior.

## Prerequisites

1. **frida** — `frida --version` (install: `pip3 install frida-tools`)
2. **frida-server** — Must be running on target device/emulator
3. **USB debugging** — `adb devices` (for Android)
4. **Target app running** — Verify process is visible to Frida

## Execution Flow

```
User specifies target app + hook target
      ↓
Verify frida-server running on device
      ↓
List processes: frida-ps
      ↓
Attach or spawn target app
      ↓
Inject JavaScript hook script
      ↓
Collect and present intercepted data
```

## Common Hooks

### List Running Processes
```bash
frida-ps -U
```

### Attach to Process (Interactive)
```bash
frida -U -n <package_name>
```

### Load Script File
```bash
frida -U -n <package_name> -l <script.js>
```

### SSL Pinning Bypass
```javascript
// Common SSL pinning bypass pattern
Java.perform(function() {
  var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  var SSLContext = Java.use("javax.net.ssl.SSLContext