---
name: rev-symbol
description: Activate when the user wants to analyze, resolve, or manage symbols in binary files. Use for symbol table extraction, import/export analysis, symbol renaming, or identifying library functions in ELF/Mach-O/PE binaries.
---

# Symbol Analyzer — Binary Symbol Analysis

**Announce:** "Using rev-symbol skill — symbol analysis mode engaged."

> This is the lean entry point. For the full surface — the per-format command
> catalog, the symbol classification table, and stripped-binary recovery
> techniques — read [`reference.md`](references/reference.md) in this skill directory when
> you need it.

## Overview

Analyze symbol tables in binary files (ELF, Mach-O, PE, DEX). Extract import/export tables, resolve library functions, identify stripped symbols, and assist in symbol recovery for reverse engineering.

## Prerequisites

1. **readelf** (Linux ELF) — `readelf -s <binary>`
2. **nm** — `nm <binary>` (symbol list)
3. **objdump** — `objdump -T <binary>` (dynamic symbols)
4. **strings** — `strings <binary>` (string extraction)
5. **rabin2** (radare2) — `rabin2 -i <binary>` (imports)

## Execution Flow

```
User provides binary file
      ↓
Identify binary format (ELF/Mach-O/PE/DEX)
      ↓
Extract symbol tables (static + dynamic)
      ↓
Classify symbols (import/export/local/weak)
      ↓
Identify stripped/missing symbols
      ↓
Suggest symbol recovery strategies
      ↓
Present analysis results
```

## Essential commands

Identify the format first, then reach for the matching extractor. The full
per-format catalog (Mach-O, PE, DEX) lives in [`reference.md`](references/reference.md).

```bash
readelf -s <binary>          # ELF symbol table
readelf --dyn-syms <binary>  # ELF dynamic symbols
nm -C <binary>               # demangled symbols (any format)
objdump -T <binary>          # dynamic symbol table
strings <binary>             # string extraction for recovery
```

## Post-Analysis

1. **Identify crypto functions** — Look for AES, RSA, SHA, MD5 symbols
2. **Find JNI functions** — `Java_*` pattern for Android native methods
3. **Map to source** — Use debug info if available (DWARF)
4. **Combine with DEX** — Use `/rev-dex-dumper` for Android native method declarations
5. **Dynamic resolution** — Use `/rev-frida` to resolve runtime symbol addresses

## Hard Rules

1. Always distinguish between static and dynamic symbols
2. Stripped binaries require FLIRT or pattern matching — document confidence level
3. Symbol names may be C++ mangled — always demangle with `nm -C` or `c++filt`
4. GOT/PLT entries are the actual hook targets for dynamic instrumentation
5. Record symbol-to-address mapping for cross-referencing with other analysis

## Chain with other skills

`/rev-dex-dumper` (Android native-method declarations) · `/rev-frida` (resolve runtime
symbol addresses) · `/rev-struct` (lay out structs at resolved addresses) · `/rev-idapython`
(script the symbol analysis).

---
**Need more?** The per-format command catalog (Mach-O / PE / DEX), the symbol
classification table, and stripped-binary recovery techniques (FLIRT,
pattern-based, string-based) live in [`reference.md`](references/reference.md).
