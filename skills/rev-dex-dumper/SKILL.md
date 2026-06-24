---
name: rev-dex-dumper
description: Activate when the user wants to dump, disassemble, or analyze DEX files from an Android APK. Use when extracting class definitions, method signatures, or bytecode from DEX files. Works with dexdump, baksmali, or similar DEX analysis tools.
---

# DEX Dumper — Android DEX File Analysis

**Announce:** "Using rev-dex-dumper skill — DEX disassembly mode engaged."

> This is the lean entry point. For the full surface — every command pattern, the
> analysis-target matrix, and the post-analysis pivot checklist — read
> [`references/reference.md`](references/reference.md) in this skill directory when you need it.

## Overview

Dump and analyze DEX (Dalvik Executable) files from Android apk. Extract class definitions, method signatures, field references, and bytecode for reverse engineering.

## Prerequisites

1. **dexdump** (Android SDK build-tools) — `dexdump` or `$ANDROID_HOME/build-tools/<version>/dexdump`
2. **baksmali** — `baksmali --version` (for Smali disassembly)
3. **apktool** — `apktool --version` (for APK unpacking)

If a tool is missing, suggest installation (Android SDK build-tools / smali / apktool.org — see `references/reference.md`).

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

## Essential commands

```bash
apktool d <file>.apk -o <output_dir>                          # unpack APK first
dexdump -l plain <file>.dex | grep "Class descriptor"         # list all classes
baksmali d <file>.dex -o <output_dir>                         # disassemble to Smali
dexdump -d -f <file>.dex                                      # full DEX dump
```

Full command catalog, the analysis-target matrix, and the post-analysis pivot
checklist live in [`references/reference.md`](references/reference.md).

## Hard Rules

1. Always verify DEX file exists before dumping
2. Output can be very large — use grep/filter for targeted analysis
3. Clean up unpacked APK directories after analysis
4. For multi-DEX APKs, scan all DEX files (classes.dex, classes2.dex, etc.)

## Chain with other skills

`/rev-apkleaks` (scan the same APK for secrets) · `/rev-frida` (hook the classes/methods
you dumped at runtime) · `/rev-symbol` (resolve `Java_*` JNI natives into the bundled `.so`).

---
**Need more?** The complete command catalog, the analysis-target matrix, and the
post-analysis pivot checklist live in [`references/reference.md`](references/reference.md).
