# apkleaks-ai-cli.py Implementation Plan

**Goal:** 创建 `apkleaks-ai-cli.py`，将 APKLeaks 所有能力以子命令形式暴露给 AI 调用，所有输出为结构化 JSON。

**Architecture:** AI 通过 Bash 调用 `python3 apkleaks-ai-cli.py <subcommand> [options]`，获取 JSON 输出。复用现有 `apkleaks/apkleaks.py` 核心类，不重写逻辑，只增加 AI 友好的调用层。

**Tech Stack:** Python 3.8+, argparse, json, apkleaks 包 (APKLeaks 类 + util), pyaxmlparser 0.3.24

**Scope:** Medium | **Risk:** Low

---

## 10 个子命令设计 (v1.0.0)

| 子命令 | 功能 | 输入 | AI 友好性亮点 |
|--------|------|------|-------------|
| `schema` | 输出工具完整定义 | (none) | AI 自发现：无需读源码即可知道所有能力 |
| `version` | 版本信息 | (none) | AI 可确认工具版本 |
| `check` | 检查前置条件 + APK 有效性 | `-f <apk>` | 错误码分类（FILE_NOT_FOUND, INVALID_APK） |
| `info` | 提取 APK 元数据 | `-f <apk>` | 权限自动分类（network/storage/location等） |
| `scan` | 完整扫描 + 严重性分类 | `-f <apk>`, `-s <severity>`, `-p`, `-a` | 结果按严重性排序，has_critical 标志 |
| `patterns` | 列出正则模式 + 严重性 | `-v` (详细) | 按 severity 排序，AI 优先关注 critical |
| `decompile` | 反编译 APK | `-f <apk>`, `-o`, `-a` | 返回文件数和耗时 |
| `search` | 搜索反编译源码 | `-d <dir>`, `-p <regex>`, `-t <type>`, `-c <ctx>` | 文件类型过滤 + 上下文行 |
| `explain` | 解释发现类别 | `-c <category>` | AI 可向用户解释影响和修复建议 |
| `mcp` | MCP Server 模式 | (stdin JSON-RPC) | 可作为 MCP Server 集成到 Claude Code |

## JSON 响应格式

```json
// 成功
{"ok": true, "timestamp": "ISO8601", "duration_ms": 45000, "data": {...}}

// 失败
{"ok": false, "timestamp": "ISO8601", "error": "...", "error_code": "FILE_NOT_FOUND"}
```

## AI 友好性增强清单

1. **schema 子命令** — AI 无需读源码，一次调用即可了解所有能力、参数、返回值
2. **结构化错误码** — error_code 字段让 AI 可以程序化处理不同类型的错误
3. **严重性分类** — scan 结果自动标注 critical/high/medium/low/info，按严重性排序
4. **severity 过滤** — `-s critical` 只看关键发现，减少 token 消耗
5. **explain 子命令** — AI 可获取每个发现类别的解释，向用户说明影响和修复建议
6. **search 文件类型过滤** — `-t java` 只搜 Java 文件，避免 XML/资源文件噪音
7. **search 上下文行** — `-c 2` 显示匹配前后各2行，AI 理解上下文
8. **权限分类** — info 输出自动将权限分为 network/storage/location 等类别
9. **duration_ms** — AI 可向用户报告耗时
10. **MCP Server** — 可作为 MCP server 集成到 Claude Code，直接工具调用
11. **has_critical 标志** — AI 一眼判断是否有紧急发现
12. **timestamp** — 所有响应包含时间戳，便于追踪
