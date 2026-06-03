---
name: rev-dex-dumper
description: Activate when the user wants to dump, disassemble, or analyze DEX files from an Android APK. Use when extracting class definitions, method signatures, or bytecode from DEX files. Works with dexdump, baksmali, or similar DEX analysis tools.
autoInvoke: false
---

# DEX Dumper — Android DEX File Analysis

**Announce:** "Using rev-dex-dumper skill — DEX disassembly mode engaged."

## Overview

Dump and analyze DEX (Dalvik Executable) files from Android apk. Extract class definitions, method signatures, field references, and bytecode for reverse engineering.

## Prerequisites

1. **dexdump** (Android SDK build-tools) — `dexdump` or `$ANDROID_HOME/build-tools/<version>/dexdump`
2. **baksmali** — `baksmali --version` (for Smali disassembly)
3. **apktool** — `apktool --version` (for APK unpacking)

If tools are missing, suggest installation:
- dexdump: Install Android SDK build-tools
- baksmali: Download from https://github.com/JesusFreke/smali
- apktool: Download from https://apktool.org

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

### Extract String Constants
```bash
dexdump -l plain <file>.dex | grep -A5 "String data"
```

## Analysis Targets

| Target | Command Pattern | Output |
|--------|----------------|--------|
| Class list | `dexdump -l plain` | All class descriptors |
| Method signatures | `dexdump -d` | Method names + signatures |
| String table | `dexdump -f` | All string constants |
| Smali code | `baksmali d` | Disassembled bytecode |
| Field references | `dexdump -d` | Static/instance fields |
| Native methods | grep `native` | Methods with native impl |

## Post-Analysis

1. **Interesting classes** — Look for auth, crypto, network, config classes
2. **Hardcoded strings** — Check string table for URLs, keys, paths
3. **Native methods** — Flag methods declared `native` for further analysis with `/rev-symbol`
4. **Cross-reference** — Use `/rev-symbol` to trace symbol references
5. **Combine with apkleaks** — Use `/rev-apkleaks` to scan for secrets in the same APK

## Hard Rules

1. Always verify DEX file exists before dumping
2. Output can be very large — use grep/filter for targeted analysis
3. Clean up unpacked APK directories after analysis
4. For multi-DEX APKs, scan all DEX files (classes.dex, classes2.dex, etc.)