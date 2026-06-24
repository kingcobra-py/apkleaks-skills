# APKLeaks for AI Agents

[English](README.md) | **简体中文**

[![version](https://badge.fury.io/gh/dwisiswant0%2fapkleaks.svg)](https://badge.fury.io/gh/dwisiswant0%2fapkleaks.svg)
[![contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwisiswant0/apkleaks/issues)

一个**面向 AI Agent** 的 [APKLeaks](https://github.com/dwisiswant0/apkleaks) 二次开发版本。它在 Android APK 中查找密钥、API key、令牌与接口端点——但原版是给人在终端里手动运行的工具，而这个二开版本是给 **AI Agent 操作**的工具。每个接口都讲 JSON、一次调用即可自我描述、自带严重性分级，因此 Agent（Claude Code 或任意能执行 shell 的运行时）无需解析自然语言文本，就能驱动一次完整的安全审计。

它在同一个仓库里同时是三样东西：一个 **MCP 服务器**、一个**结构化 JSON CLI**，以及一个注册了九个逆向工程 **skill** 的 **Claude Code 插件**。

> [!IMPORTANT]
> 这个二开版本是设计给 *Agent 调用的，而不是给人手动敲的*。响应都是确定性、机器可读的；工具通过一次 `schema` 调用即可公布整套 API；发现项预先按严重等级排序，并带 `has_critical` 标志，可一步分诊。如果你想找的是经典的交互式 CLI，请直接跳到 [独立人类用法](#独立人类用法)。

### 功能树一览

在上游 APKLeaks 基础上二次开发、重新打造为 AI 原生工具集。一图抵千言——全部接入方式、能力与 skill 尽收一图。下图由 [`tools/feature_tree.py`](tools/feature_tree.py) 渲染（纯标准库，不依赖 Mermaid/Graphviz），并以普通 SVG 提交进仓库，因此在任意 Markdown 查看器里都能显示：

![APKLeaks for AI Agents — 功能树](docs/feature-tree.svg)

<details>
<summary>文本版（任何环境都能显示）</summary>

```text
APKLeaks for AI Agents
├─ Built on upstream
│  ├─ Fork of dwisiswant0/apkleaks
│  ├─ Scanning engine unchanged
│  └─ AI-native layer added on top
├─ Agent access surfaces
│  ├─ MCP server — 12 tools / 4 resources / 4 prompts
│  ├─ Structured-JSON CLI — 13 subcommands
│  └─ Claude Code skills — 9 rev-* skills
├─ Core capabilities
│  ├─ check / info
│  ├─ scan — severity-graded
│  ├─ decompile / search
│  ├─ explain — impact + fix
│  └─ rule add / test / remove
├─ Detection coverage
│  ├─ 95+ patterns
│  └─ 12 categories
└─ Agent contract
   ├─ ok flag + stable error_code
   ├─ schema self-discovery
   └─ has_critical triage
```

用 `python3 tools/feature_tree.py` 可重新生成（写出 `docs/feature-tree.svg` 并打印此树）。

</details>

### 目录

- [为什么要做这个二开](#为什么要做这个二开)
- [Agent 如何使用它](#agent-如何使用它)
  - [1. MCP 服务器——原生工具调用](#1-mcp-服务器原生工具调用)
  - [2. 结构化 JSON CLI——任意 shell](#2-结构化-json-cli任意-shell)
  - [3. Claude Code skills——按意图触发](#3-claude-code-skills按意图触发)
  - [一个典型的 Agent 循环](#一个典型的-agent-循环)
- [Agent 契约](#agent-契约)
- [能力参考](#能力参考)
  - [AI-CLI 子命令](#ai-cli-子命令)
  - [MCP 工具](#mcp-工具)
  - [MCP 资源](#mcp-资源)
  - [MCP 提示词](#mcp-提示词)
- [Skills 目录](#skills-目录)
- [仓库结构](#仓库结构)
- [安装——安装插件](#安装安装插件)
- [检测覆盖范围](#检测覆盖范围)
- [独立人类用法](#独立人类用法)
- [许可证](#许可证)
- [致谢](#致谢)

---

## 为什么要做这个二开

上游的 APKLeaks 是一个不错的人类 CLI：指向一个 `.apk`，读一份文本报告。但当 *操作者是一个 LLM* 时，这套契约就崩了。Agent 无法可靠地爬取带颜色的 stdout 输出，无法在不读源码的情况下知道有哪些参数，也无法靠一句话来给自己的计划分支。它需要结构化的输入输出、稳定的错误码，以及把工具当作一等函数来调用的方式。

于是这个二开版本在原引擎之上包了这样一层——**完全没有改动扫描逻辑**——专为这种操作者打造：

- **每个接口都是确定性 JSON。** 每次调用都返回 `{"ok": true, "data": …}` 或 `{"ok": false, "error_code": …}`。无需解析，无需猜测。
- **一次调用即可自发现。** 一次 `schema` 请求就返回全部子命令、参数和返回结构——Agent 不必打开任何文件就能学到整套 API。
- **严重性分级的发现项。** 结果预先分类为 `critical → high → medium → low → info`，并带 `has_critical` 标志，Agent 可以分诊和过滤（`-s critical`），而不必把所有结果重读一遍。
- **原生工具调用。** 完整的 MCP 服务器把引擎暴露给 Claude Code，中间无需 Bash 子进程。
- **即插即用的 skills。** 九个逆向工程 skill，Agent 可按名调用，并能彼此顺畅串联。

## Agent 如何使用它

共有三种接入方式，底层是 *同一个* 引擎、*同一种* JSON 外壳——因此针对其中一种写的工作流可以原封不动迁移到另一种。Agent 根据自身运行时哪种代价最低来选择：

| 你的 Agent 运行时 | 用哪种接入 | 原因 |
|---|---|---|
| 配好 MCP 的 Claude Code | **MCP 工具**（`apkleaks_*`） | 原生工具调用，无子进程，带类型化 schema |
| 任何能执行 shell 的 Agent | **结构化 JSON CLI** | 零配置——经 Bash 调用、解析 stdout |
| 按意图触发的 Claude Code 会话 | **`/rev-apkleaks` skill** | 替你编排好该调的那几个调用 |

从配置最少的那种开始即可，三者的响应结构完全一致。

### 1. MCP 服务器——原生工具调用

Claude Code 的首选方式。Agent 通过 [Model Context Protocol](https://modelcontextprotocol.io/)（stdio）直接调用 `apkleaks_*` 工具——无需 Bash，无需解析 stdout。

```jsonc
// Agent 大致这样调用一个工具：
apkleaks_scan({ "file": "/path/app.apk", "severity": "critical" })
// → { "ok": true, "data": { "has_critical": true, "findings": [ ... ] } }
```

安装插件（见下文）后该服务器会被自动注册——或者也可以手动写进 `.claude/settings.json`（见 [安装](#安装安装插件)）。

### 2. 结构化 JSON CLI——任意 shell

适用于任何能执行 shell 命令的 Agent。通过 Bash 工具调用 `apkleaks-ai-cli.py <子命令>`，再解析 stdout 里的 JSON——无需 MCP、无需插件、无需配置。

```bash
python3 apkleaks-ai-cli.py schema                       # 发现所有能力
python3 apkleaks-ai-cli.py scan -f app.apk -s critical  # 只分诊 critical 级别发现
python3 apkleaks-ai-cli.py explain -c AWS_API_Key       # 某类别的影响 + 修复建议
```

每次调用都会在 stdout 打印同一种外壳——下面是一个真实的 `version` 响应：

```json
{
  "ok": true,
  "timestamp": "2026-06-24T14:02:03+0800",
  "data": { "version": "1.0.0", "python": "3.12.3" }
}
```

### 3. Claude Code skills——按意图触发

仓库根目录**本身就是一个 Agent Skill**——根目录下有一个 `SKILL.md`（`name: apkleaks`），扫描器与规则就在其旁，因此把整个仓库丢进任意 Agent 的 skills 目录（`.claude/skills/apkleaks/`、`~/.claude/skills/`，或打包成 zip 上传）即可作为开箱即用的 skill 使用。它**同时**也是一个可安装的 Claude Code 插件：安装后（见 [安装](#安装安装插件)），内置的 MCP 服务器以及 9 个配套的 `rev-*` skill——从 `skills/` 自动发现——便可在任意会话中使用，并按意图触发（例如 `/rev-apkleaks`），替 Agent 编排相应的 CLI/MCP 调用。详见 [Skills 目录](#skills-目录)。

### 一个典型的 Agent 循环

一次完整审计其实就是几次串联调用，每一步都根据上一步的响应来分支：

```text
schema            → 提前一次性了解全部能力与返回结构
check  -f app.apk → 确认 jadx + pyaxmlparser 就位、APK 有效        （按 ok 分支）
info   -f app.apk → 包名、SDK 等级、已分类的权限                    （不反编译）
scan   -f app.apk -s high   → 反编译 + 95 条规则扫描，仅 high 及以上 （按 has_critical 分支）
explain -c <category>       → 每个发现项的影响 + 修复建议            （每类别一次）
search -d <dir> -p <regex>  → 切入反编译源码看上下文                 （验证某个命中）
```

因为每一步都返回 `ok` 和一个稳定的 `error_code`，Agent 永远无需解析自然语言文本来决定下一步做什么。

## Agent 契约

Agent 消费的一切都遵循同一种可预测的结构。

**响应外壳**——每个子命令和工具都返回下列之一：

```json
{"ok": true,  "timestamp": "ISO-8601", "duration_ms": 123, "data": { /* 结果 */ }}
{"ok": false, "timestamp": "ISO-8601", "error": "人类可读文本", "error_code": "FILE_NOT_FOUND"}
```

- **`ok`**——用于分支判断的单一布尔值。`error_code` 稳定且可机器匹配（`FILE_NOT_FOUND`、`INVALID_APK`、`NO_FINDINGS` 等），在成功时也可能出现（如 `NO_FINDINGS`）。
- **`data`**——载荷。对于 `scan`，包含 `has_critical` 标志，且发现项按 `critical → info` 排序。
- **`duration_ms`**——便于 Agent 向用户汇报耗时。

**自发现**——先调用 `schema`（CLI）或 `apkleaks_schema`（MCP）；一次往返即可得到全部子命令、参数和返回结构，无需读源码。

**严重性与 token 经济性**——发现项已预先分级。用 `-s critical`（CLI）/ `severity`（MCP）过滤，只保留关键内容，把读结果消耗的 token 降到最低。

**实例**——扫描暴露出某个类别后，一次 `explain` 调用就能返回 Agent 可直接据以行动的严重性、影响和修复建议（真实输出）：

```jsonc
// python3 apkleaks-ai-cli.py explain -c Anthropic_API_Key
{
  "ok": true,
  "data": {
    "category": "Anthropic_API_Key",
    "severity": "critical",
    "description": "Anthropic API keys (sk-ant-api03- prefix) provide access to Claude ... Revoke at console.anthropic.com.",
    "impact": "Immediate credential compromise. Rotate and revoke exposed secrets without delay.",
    "remediation": "Rotate the exposed credential immediately. Move secrets to environment variables or a secrets manager. Audit access logs for unauthorized use."
  }
}
```

`explain` 接受部分匹配 / 大小写不敏感的类别名，因此 Agent 可以把 `scan` 输出里的发现项名称直接传进来，无需先做归一化。

## 能力参考

### AI-CLI 子命令

`python3 apkleaks-ai-cli.py <子命令>`——共 13 个子命令，全部返回上述 JSON 外壳。

| 子命令 | 用途 | 关键参数 |
|-----------|---------|-----------|
| `schema` | 自我描述全部能力（Agent 发现） | —— |
| `version` | 工具 / Python 版本 | —— |
| `check` | 检查前置条件 + APK 有效性（结构化错误码） | `-f` |
| `info` | APK 元数据 + 权限自动分类（不反编译） | `-f` |
| `scan` | 完整扫描：反编译 + 正则 + 严重性（已排序，含 `has_critical`） | `-f`、`-s`、`-p`、`-a`、`--json` |
| `patterns` | 列出检测规则及其严重等级 | `-v` |
| `decompile` | 将 APK 反编译为 Java 源码（返回文件数 + 耗时） | `-f`、`-o`、`-a` |
| `search` | 正则搜索反编译源码，支持文件类型过滤 + 上下文 | `-d`、`-p`、`-t`、`-c`、`-l` |
| `explain` | 解释某个发现类别（影响 + 修复建议） | `-c` |
| `rule-add` | 运行时添加自定义检测规则（内存中） | `-n`、`-r`、`-s` |
| `rule-remove` | 移除运行时添加的规则 | `-n` |
| `rule-test` | 添加前用样例文本校验正则 | `-r`、`-t` |
| `mcp` | 以 MCP 服务器模式通过 stdio 运行 | —— |

> [!NOTE]
> `rule-add` / `rule-remove` 修改的是 **内存中** 的规则集，因此只在单个长驻进程内有效——即一个存活的 MCP 会话。在多次独立的一次性 CLI 调用之间，规则集会重置。

### MCP 工具

`tools/list` 返回 12 个带完整 JSON Schema（含说明、枚举、默认值）的工具定义。MCP 服务器使用 **惰性导入**——`initialize` / `ping` / `tools/list` 在未安装 `pyaxmlparser` 时也能工作，只有实际的 scan/info/decompile 调用才需要该依赖。

| 工具 | 说明 | 关键参数 |
|------|-------------|----------------|
| `apkleaks_schema` | 发现全部能力 | —— |
| `apkleaks_version` | 版本信息 | —— |
| `apkleaks_check` | 检查前置条件 + APK 有效性 | `file` |
| `apkleaks_info` | APK 元数据（不反编译） | `file` |
| `apkleaks_scan` | 完整扫描 + 严重性分级 | `file`、`severity`、`pattern`、`jadx_args`、`output`、`json_output` |
| `apkleaks_patterns` | 列出正则检测规则 | `verbose` |
| `apkleaks_decompile` | 反编译为 Java 源码 | `file`、`output_dir`、`jadx_args` |
| `apkleaks_search` | 搜索反编译源码 | `dir`、`pattern`、`type`、`context`、`limit` |
| `apkleaks_explain` | 解释某个发现类别 | `category` |
| `apkleaks_rule_add` | 添加自定义检测规则（运行时） | `name`、`regex`、`severity` |
| `apkleaks_rule_remove` | 移除运行时添加的规则 | `name` |
| `apkleaks_rule_test` | 用样例文本测试正则 | `regex`、`sample`、`name`、`severity` |

### MCP 资源

`resources/list` 暴露配置文件 + 一个动态源码读取器；`resources/read` 返回其内容。

| URI | 说明 | MIME |
|-----|-------------|------|
| `apkleaks:///config/regexes` | 全部 95+ 条正则规则定义 | application/json |
| `apkleaks:///config/severity-map` | 类别 → 严重等级映射 | application/json |
| `apkleaks:///config/explanations` | 每个类别的影响 + 修复建议 | application/json |
| `apkleaks:///source/{path}` | 读取任意反编译源码文件（动态） | 自动识别 |

### MCP 提示词

`prompts/list` 返回 4 个参数化的分析模板，Agent 可将其展开为完整工作流。

| 提示词 | 说明 | 参数 |
|--------|-------------|-----------|
| `security-audit` | 带修复建议的完整安全审计 | `apk_path`、`severity_filter` |
| `credential-rotation` | 凭据轮换计划 | `apk_path` |
| `api-inventory` | API 端点清单 | `apk_path` |
| `permission-risk` | 权限风险评估 | `apk_path` |

## Skills 目录

`skills/` 下的 9 个 `rev-*` skill，插件安装后自动发现。`rev-apkleaks` 驱动本工具；其余覆盖 Agent 常与之串联的相邻逆向工程任务。

每个 skill 都采用**渐进式披露**：精简的 `SKILL.md` 在触发时加载（模式选择、核心工作流、契约、硬性规则），而单独的 `references/reference.md` 仅在 Agent 需要完整细节时才读取（每个子命令的参数、完整的 MCP 生命周期、资源/提示词目录、全部错误码）——让常驻上下文保持精简，同时完整深度始终只差一次读取。

| Skill | 触发方式 | 功能 |
|-------|--------|--------------|
| **rev-apkleaks** | `/rev-apkleaks` | 扫描 APK 中的密钥、key、令牌与端点（CLI + MCP）。 |
| **rev-dex-dumper** | `/rev-dex-dumper` | 转储 / 反汇编 DEX——类定义、方法签名、字节码。 |
| **rev-frida** | `/rev-frida` | 动态插桩：hook、跟踪、SSL pinning / root 检测绕过。 |
| **rev-idapython** | `/rev-idapython` | 用 IDA Pro Python 脚本做自动化二进制分析。 |
| **rev-ios-dump** | `/rev-ios-dump` | 从越狱设备转储 / 解密 iOS 应用（IPA）。 |
| **rev-struct** | `/rev-struct` | 从内存访问模式重建 struct/class 布局与字段偏移。 |
| **rev-symbol** | `/rev-symbol` | 符号表提取、导入/导出及库函数分析。 |
| **rev-u3d-dump** | `/rev-u3d-dump` | 提取 Unity3D 资源（Assembly-CSharp.dll、资源包、shader）。 |
| **rev-unicorn-debug** | `/rev-unicorn-debug` | 用 Unicorn 模拟 / 调试 CPU 指令（ARM/x86/MIPS…）。 |

## 仓库结构

本仓库按 **Claude Code 插件 + skills 集合** 的形态组织（与 `anthropics/skills` 同款），因此既能作为 marketplace 插件安装，也能作为单个 skill 整体丢入。定义仓库的顶层标记是 **`plugin.json`**——而不是根目录的 `SKILL.md`。

```text
apkleaks-skills/
├── plugin.json                 # 顶层插件清单（元数据 + MCP 服务器）
├── .claude-plugin/
│   ├── plugin.json             # 内置插件清单（使用 ${CLAUDE_PLUGIN_ROOT}）
│   └── marketplace.json        # marketplace 列表（source: "./"）——可被 /plugin marketplace add
├── skills/                     # 9 个自动发现的 rev-* skill
│   └── rev-apkleaks/
│       ├── SKILL.md            # 精简入口（触发时加载）
│       ├── references/
│       │   └── reference.md    # 深度参考（按需读取）
│       └── LICENSE.txt         # Apache-2.0，镜像根 LICENSE
├── SKILL.md                    # 可选的根 skill——整个仓库也能作为单个 drop-in skill
├── references/reference.md     # 其按需深度参考
├── apkleaks-ai-cli.py          # AI-CLI：13 个子命令 + MCP 服务器（Agent 入口）
├── apkleaks.py                 # 原版人类 CLI 入口
├── apkleaks/                   # 核心引擎（反编译、扫描、提取——逻辑未改）
├── config/regexes.json         # 95+ 条检测规则，覆盖 12 个类别
├── LICENSE                     # Apache-2.0
└── THIRD_PARTY_NOTICES.md      # 对内置 / 衍生依赖的归属声明
```

每个 `skills/<name>/` 目录都遵循规范的 Agent Skill 结构——`SKILL.md` + `references/reference.md` + `LICENSE.txt`。`SKILL.md` 的 frontmatter 只携带规范认可的 `name` 与 `description`。随时可用 `claude plugin validate .` 校验清单。

## 安装——安装插件

这里不是"装好后手动扫描"，而是把工具接入 Agent 的运行时。

**Agent 环境需要的前置条件：**

- Python ≥ 3.8
- [`jadx`](https://github.com/skylot/jadx)——首次反编译时若缺失会自动下载
- `pyaxmlparser ≥ 0.3.24`——仅 `scan` / `info` / `decompile` 需要（MCP 生命周期方法无需它）
- [`uv`](https://docs.astral.sh/uv/)——内置 MCP 服务器用它自动装依赖（`curl -LsSf https://astral.sh/uv/install.sh | sh`）

### 推荐：作为 Claude Code 插件安装

仓库自带 `.claude-plugin/` 清单，因此 Claude Code 可将其作为 marketplace 插件安装。一步即可注册全部 9 个 `rev-*` skill **以及** `apkleaks` MCP 服务器——无需手动编辑 `settings.json`：

```text
/plugin marketplace add android-security-engineer/apkleaks-skills
/plugin install apkleaks
```

MCP 服务器通过 `uv` 从插件的安装目录启动（清单使用 `${CLAUDE_PLUGIN_ROOT}`，因此无论插件落在哪里路径都能解析）。skill 从 `skills/` 自动发现，无需额外配置。

### 备选：手动接入 MCP 服务器

若要在本仓库上做本地开发，或运行时不支持插件，可直接把 MCP 服务器写进项目的 `.claude/settings.json`——任选一种运行方式，三种均支持：

#### 方式一：`uv run`（推荐）

自动将依赖安装到隔离的虚拟环境，无需手动 `pip install`。

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

安装 uv：`curl -LsSf https://astral.sh/uv/install.sh | sh`

#### 方式二：`pipx run`

临时虚拟环境 + 依赖，适合不使用 uv 的用户。

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

安装 pipx：`pip install pipx` 或 `brew install pipx`

#### 方式三：`python3`（手动）

直接执行，需先 `pip install -e .`（或 `pip install -r requirements.txt`）。

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

把配置放进项目的 `.claude/settings.json`，Claude Code 在打开项目时会自动启动 MCP 服务器。（CLI 方式无需任何设置——Agent 直接通过 Bash 调用即可。）

## 检测覆盖范围

**95+ 条正则规则，覆盖 12 个类别**，每条都映射到一个严重等级和一段说明（影响 + 修复建议）：

云服务商 · AI/大模型 key · 即时通讯 · 支付 · DevOps · 监控 · CDN · 托管 · 身份认证 · 私钥 · Android 专属 · 通用。

Agent 可通过 `patterns`（CLI）/ `apkleaks_patterns`（MCP）或 `apkleaks:///config/regexes` 资源读取实时规则集，并用 `rule-add` 在运行时扩展。也可以将自定义静态规则以 JSON 文件形式提供给底层引擎（见 [独立人类用法](#独立人类用法)）。

## 独立人类用法

如果你想手动跑一次扫描，原始的人类 CLI 仍然可用——但对于 Agent 用途，请优先使用上面的接入方式。

<details>
<summary>点击展开经典人类 CLI</summary>

### 安装

```bash
$ pip3 install apkleaks                       # 通过 PyPi
$ docker pull dwisiswant0/apkleaks:latest     # 或通过 Docker
```

### 扫描

```bash
$ apkleaks -f ~/path/to/file.apk
# 源码方式
$ python3 apkleaks.py -f ~/path/to/file.apk
# 或使用 Docker
$ docker run -it --rm -v /tmp:/tmp dwisiswant0/apkleaks:latest -f /tmp/file.apk
```

### 选项

| 参数 | 说明 | 示例 |
|----------|-------------|---------|
| `-f, --file` | 要扫描的 APK 文件 | `apkleaks -f file.apk` |
| `-o, --output` | 将结果写入文件 _(未指定则随机)_ | `apkleaks -f file.apk -o results.txt` |
| `-p, --pattern` | 自定义规则 JSON 路径 | `apkleaks -f file.apk -p custom-rules.json` |
| `-a, --args` | 反编译器参数 | `apkleaks -f file.apk --args="--deobf --log-level DEBUG"` |
| `--json` | 以 JSON 格式保存 | `apkleaks -f file.apk -o results.json --json` |

**自定义规则**——通过 `--pattern /path/to/custom-rules.json` 以 JSON 形式提供你自己的搜索规则。若省略，则使用默认的 [regexes.json](https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json)。

```json
// custom-rules.json
{ "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}" }
```

**反编译器参数**——通过 `-a/--args` 透传 jadx 参数，例如 `--args="--threads-count 5"`。

> [!WARNING]
> 注意默认的反编译器参数，以避免冲突。

</details>

## 许可证

`apkleaks` 基于 **Apache 2.0 许可证** 发布——见 [`LICENSE`](LICENSE)。内置与衍生组件（jadx、dex2jar、pyaxmlparser、LinkFinder、gf、truffleHogRegexes，以及上游 APKLeaks 引擎）各自携带自身许可证；完整归属见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 致谢

构建于 [dwisiswant0/apkleaks](https://github.com/dwisiswant0/apkleaks) 及众多贡献者的工作之上：

- [@ndelphit](https://github.com/ndelphit) —— 感谢启发本工具诞生的 `apkurlgrep`。
- [@dxa4481](https://github.com/dxa4481) 及 `truffleHogRegexes` 的贡献者们。
- [@GerbenJavado](https://github.com/GerbenJavado) 和 [@Bankde](https://github.com/Bankde) —— `LinkFinder` 中用于发现 URL、端点及参数的规则。
- [@tomnomnom](https://github.com/tomnomnom/gf) —— `gf` 规则。
- [@pxb1988](https://github.com/pxb1988) —— `dex2jar` 反编译器。
- [@subho007](https://github.com/ph4r05) —— 独立的 APK 解析器。
- `SHA2048#4361` _(Discord)_ —— Python3 移植帮助。
- [@Ry0taK](https://github.com/Ry0taK) —— 上报了一个 [OS 命令注入漏洞](https://github.com/dwisiswant0/apkleaks/security/advisories/GHSA-8434-v7xw-8m9x)。
- [@dee__see](https://twitter.com/dee__see) —— 整理的 `NotKeyHacks` 令牌库。
- [所有贡献者](https://github.com/dwisiswant0/apkleaks/graphs/contributors)。
