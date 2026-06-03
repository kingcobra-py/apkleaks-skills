# Research: 当前 SKILLS 改造现状

**Question:** 当前环境中有哪些 SKILLS？改造情况如何？
**Context:** 用户想了解 SKILLS 配置的全貌
**Deliverable:** SKILLS 配置现状报告
**Time Box:** 已完成
**Scope:** Small

---

## 1. 系统级 SKILLS（Claude Code 内置，共 21 个）

这些 SKILLS 由 Claude Code 系统提供，定义在运行时，不在本地文件系统中。

### 1.1 工作流 Skills（7 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **brainstorming** | 任何创意工作前 | 探索用户意图、需求和设计 |
| **writing-plans** | 编写实现计划 | 多阶段规划（类型检测→调研→计划→自检→执行选择） |
| **executing-plans** | 有已写计划需执行 | 计划审查→执行决策 |
| **dispatching-parallel-agents** | 2+ 独立任务 | 分析→派发决策 |
| **subagent-driven-development** | 执行含独立任务的计划 | 任务分析→派发策略 |
| **skill-graph** | 会话开始 | 加载完整技能有向图 |
| **using-superpowers** | 任何对话开始 | 建立如何发现和使用 Skills |

### 1.2 代码质量 Skills（4 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **simplify** | 审查已改代码 | 检查复用性、质量和效率 |
| **verification-before-completion** | 声称工作完成前 | 收集证据→完成决策 |
| **test-driven-development** | 实现功能/修复前 | 测试设计→实现策略 |
| **systematic-debugging** | 遇到 bug/测试失败 | 调查→修复策略 |

### 1.3 Git/分支 Skills（2 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **finishing-a-development-branch** | 实现完成、测试通过 | 验证→工作流选择 |
| **using-git-worktrees** | 需要隔离的功能工作 | 目录分析→创建 |

### 1.4 Code Review Skills（2 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **requesting-code-review** | 完成任务/实现功能前 | 范围分析→审查者派发 |
| **receiving-code-review** | 收到代码审查反馈 | 反馈分析→实现 |

### 1.5 配置/优化 Skills（4 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **update-config** | 配置 settings.json | 自动化行为、权限、环境变量 |
| **keybindings-help** | 自定义键盘快捷键 | 重绑键、添加组合键 |
| **fewer-permission-prompts** | 减少权限提示 | 扫描→添加白名单 |
| **zero-confirm-mode** | 零确认模式 | — |

### 1.6 其他 Skills（4 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **loop** | 循环执行任务 | 定时运行提示/命令 |
| **claude-api** | 构建 Claude API 应用 | SDK 调试、缓存优化、版本迁移 |
| **writing-skills** | 编写新 Skill | — |
| **init** | 初始化项目 | — |

### 1.7 审查 Skills（2 个）

| Skill | 触发条件 | 功能 |
|-------|---------|------|
| **review** | 代码审查 | — |
| **security-review** | 安全审查 | — |

---

## 2. 本地自定义 Skills（8 个逆向工程类 + 1 个规划类）

### 2.1 逆向工程 Skills（目录已创建，内容待填充）

以下 8 个 Skill 目录存在于 `/data/local/tmp/workspace/.claude/skills/`，但**目前都是空目录**，尚未写入定义文件：

| Skill | 目录 | 用途（基于系统注册描述） | 状态 |
|-------|------|----------------------|------|
| **rev-dex-dumper** | `rev-dex-dumper/` | DEX 文件转储与分析 | 空目录 |
| **rev-frida** | `rev-frida/` | Frida 动态插桩 | 空目录 |
| **rev-idapython** | `rev-idapython/` | IDA Pro Python 脚本 | 空目录 |
| **rev-ios-dump** | `rev-ios-dump/` | iOS 应用转储 | 空目录 |
| **rev-struct** | `rev-struct/` | 通过内存访问模式重建数据结构 | 空目录 |
| **rev-symbol** | `rev-symbol/` | 符号分析与处理 | 空目录 |
| **rev-u3d-dump** | `rev-u3d-dump/` | Unity3D 资源转储 | 空目录 |
| **rev-unicorn-debug** | `rev-unicorn-debug/` | Unicorn CPU 模拟器调试 | 空目录 |

**改造状态：** 目录骨架已搭建，但所有 skill.md 定义文件均未创建。这些 Skill 目前只能通过系统注册的描述信息被识别，但无法被实际调用执行。

### 2.2 规划类 Skill

| Skill | 目录 | 用途 | 状态 |
|-------|------|------|------|
| **writing-plans** | `writing-plans/` | 多阶段实现计划编写 | 已有完整定义（当前会话正在使用） |

---

## 3. 环境配置

### 3.1 settings.json

文件路径：`/data/local/tmp/workspace/.claude/settings.json`

```json
{
  "theme": "dark",
  "skipDangerousModePermissionPrompt": true,
  "statusLine": {
    "type": "command",
    "command": "/data/local/tmp/workspace/.claude/statusline.sh"
  }
}
```

| 配置项 | 值 | 说明 |
|--------|---|------|
| `theme` | `"dark"` | 深色主题 |
| `skipDangerousModePermissionPrompt` | `true` | 跳过危险模式确认提示 |
| `statusLine` | 自定义命令 | 运行 statusline.sh 显示模型名+项目文件夹名 |

### 3.2 自定义状态栏

文件路径：`/data/local/tmp/workspace/.claude/statusline.sh`

功能：从 JSON 输入中提取 `display_name` 和 `project_dir`，格式化为 `ModelName | FolderName` 显示。

---

## 4. 改造总结

### 已完成

| 项目 | 详情 |
|------|------|
| 逆向 Skills 骨架 | 8 个 rev-* 目录已创建 |
| 规划 Skill | writing-plans 已有完整定义，正在使用 |
| 状态栏定制 | 自定义 statusline.sh 显示模型+项目 |
| 权限优化 | skipDangerousModePermissionPrompt 已启用 |

### 待完成

| 项目 | 详情 | 优先级 |
|------|------|--------|
| **rev-dex-dumper 定义** | 空目录，需创建 skill.md | 高 |
| **rev-frida 定义** | 空目录，需创建 skill.md | 高 |
| **rev-idapython 定义** | 空目录，需创建 skill.md | 高 |
| **rev-ios-dump 定义** | 空目录，需创建 skill.md | 中 |
| **rev-struct 定义** | 空目录，需创建 skill.md | 中 |
| **rev-symbol 定义** | 空目录，需创建 skill.md | 中 |
| **rev-u3d-dump 定义** | 空目录，需创建 skill.md | 中 |
| **rev-unicorn-debug 定义** | 空目录，需创建 skill.md | 中 |
| **CLAUDE.md** | 项目级 CLAUDE.md 不存在 | 中 |
| **MEMORY.md** | 记忆系统未初始化 | 低 |

---

## 5. 行动建议

1. **优先填充 8 个 rev-* Skills 的定义文件** — 这些是本项目的核心差异化能力，目前只有空壳
2. **创建项目级 CLAUDE.md** — 为 AI-apkleaks 项目定义专属上下文和规则
3. **初始化 MEMORY.md** — 建立跨会话持久记忆
4. **考虑为 APKLeaks 项目创建专属 Skill** — 例如 `rev-apk-scanner`，整合 APKLeaks 工具链
