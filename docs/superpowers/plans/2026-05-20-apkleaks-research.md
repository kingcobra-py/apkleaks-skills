# Research: APKLeaks 项目功能与架构分析

**Question:** APKLeaks 项目是什么？能做什么？架构如何？
**Context:** 用户希望了解项目功能和能力，为后续工作提供基础认知
**Deliverable:** 项目全景分析报告
**Time Box:** 已完成
**Scope:** Small

---

## 1. 项目定位

APKLeaks (v2.6.3) 是一个 **Android APK 安全扫描工具**，用于从反编译的 APK 源码中提取 URI、端点和敏感信息（API 密钥、Token、凭证、私钥等）。

- **作者:** dwisiswant0
- **许可证:** Apache 2.0
- **Python:** >= 3.8
- **仓库:** github.com/dwisiswant0/apkleaks

---

## 2. 核心能力

### 2.1 APK 反编译

使用 **jadx v1.2.0** 反编译器，将 APK 文件反编译为 Java 源码。jadx 在首次使用时自动下载，也可通过 Docker 镜像预装。

### 2.2 敏感信息扫描

内置 **60+ 正则表达式模式**（`config/regexes.json`），覆盖以下类别：

| 类别 | 检测内容 |
|------|---------|
| **云服务凭证** | AWS Access Key、AWS S3 Bucket、Google API Key、GCP OAuth、Firebase、Heroku API Key |
| **社交平台 Token** | Facebook Access Token/Secret/OAuth、Twitter Access Token/Secret/OAuth、Slack Token/Webhook、Discord BOT Token |
| **支付服务密钥** | Stripe API Key（含受限密钥）、Square Access Token/OAuth Secret、PayPal Braintree Access Token |
| **认证模式** | Authorization Basic/Bearer、Basic Auth Credentials、JSON Web Token、Cloudinary Basic Auth |
| **私钥** | RSA Private Key、SSH DSA/EC Private Key、PGP Private Key Block |
| **通用模式** | Generic API Key、Generic Secret、URL 中的密码、IP 地址、MAC 地址 |
| **URL/端点发现** | LinkFinder 模式（全面 URL/端点提取）、Mailto |
| **CTF Flag** | DEFCON、HackerOne、HackTheBox、TryHackMe |
| **其他** | Artifactory API Token/Password、MailChimp/Mailgun API Key、Twilio API Key、GitHub Access Token |

### 2.3 自定义模式

支持通过 `-p` 参数加载自定义正则表达式 JSON 文件，扩展扫描范围。

### 2.4 多种输出格式

- **纯文本**（默认）：分类列出各模式匹配结果
- **JSON**（`--json`）：结构化输出，包含包名和匹配数组

---

## 3. 工作流程

```
用户输入 APK 文件
      ↓
  完整性检查（jadx 存在性 + APK 有效性）
      ↓
  jadx 反编译 APK → Java 源码
      ↓
  多线程扫描（每个正则模式一个线程）
  遍历所有反编译文件 → 逐行匹配
      ↓
  提取与去重
  过滤误报（如 LinkFinder 的资源路径）
      ↓
  输出结果（文本/JSON）
      ↓
  清理临时文件
```

---

## 4. 项目架构

```
AI-apkleaks/
├── apkleaks.py              # 顶层入口，调用 cli.main()
├── apkleaks/                # 主 Python 包
│   ├── cli.py               # CLI 参数解析 + 管道编排
│   ├── apkleaks.py          # 核心类 APKLeaks（完整扫描逻辑）
│   ├── colors.py            # ANSI 颜色码
│   └── utils.py             # 文件遍历 + 正则搜索
├── config/
│   └── regexes.json         # 60+ 正则模式定义
├── pyproject.toml           # 构建配置（pip 安装入口）
├── requirements.txt         # 运行依赖：pyaxmlparser
├── Dockerfile               # Docker 镜像（python:3-slim + jadx）
└── VERSION                  # v2.6.3
```

### 关键模块

| 模块 | 职责 |
|------|------|
| `cli.py` | 参数解析（`-f`, `-o`, `-p`, `-a`, `--json`）、管道编排 |
| `apkleaks.py` | APKLeaks 类：完整性检查、jadx 下载、反编译、扫描、提取、清理 |
| `utils.py` | `finder()` 核心搜索：遍历目录树 + 逐行正则匹配 + 去重排序 |
| `regexes.json` | 所有检测模式定义，可自定义扩展 |

---

## 5. CLI 用法

```bash
# 基本用法
apkleaks -f /path/to/file.apk

# 指定输出文件
apkleaks -f /path/to/file.apk -o results.txt

# 自定义正则模式
apkleaks -f /path/to/file.apk -p custom_patterns.json

# 传递 jadx 参数
apkleaks -f /path/to/file.apk -a "--no-res"

# JSON 输出
apkleaks -f /path/to/file.apk --json

# Docker 运行
docker run -it --rm -v /tmp:/tmp dwisiswant0/apkleaks -f /tmp/file.apk
```

---

## 6. 安装方式

| 方式 | 命令 |
|------|------|
| PyPI | `pip3 install apkleaks` |
| 源码 | `git clone` + `pip3 install -r requirements.txt` + `python3 apkleaks.py` |
| Docker | `docker pull dwisiswant0/apkleaks:latest` |

---

## 7. 技术栈

| 组件 | 版本/说明 |
|------|----------|
| Python | >= 3.8 |
| jadx | v1.2.0（自动下载） |
| pyaxmlparser | >= 0.3.24（APK 元数据解析） |
| Docker | python:3-slim + OpenJDK 17 + jadx 1.2.0 |

---

## 8. 总结

APKLeaks 是一个专注于 **Android 应用安全审计** 的轻量工具，核心价值在于：

1. **自动化反编译** — 一键 jadx 反编译，无需手动操作
2. **全面敏感信息检测** — 60+ 内置模式覆盖主流云服务、社交、支付、认证场景
3. **可扩展** — 支持自定义正则模式文件
4. **多种部署** — pip、源码、Docker 三种安装方式
5. **多线程扫描** — 每个正则模式独立线程，提高扫描效率

典型使用场景：渗透测试中对 Android 应用进行信息收集、安全审计中发现硬编码凭证、CTF 竞赛中提取 Flag。
