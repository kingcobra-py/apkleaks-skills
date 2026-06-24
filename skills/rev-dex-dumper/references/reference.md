# rev-dex-dumper — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full command catalog, the analysis-target matrix, and the post-analysis pivot
> checklist.

## Tool installation

If tools are missing, suggest installation:
- dexdump: Install Android SDK build-tools
- baksmali: Download from https://github.com/JesusFreke/smali
- apktool: Download from https://apktool.org

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
