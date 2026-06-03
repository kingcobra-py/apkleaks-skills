---
name: rev-symbol
description: Activate when the user wants to analyze, resolve, or manage symbols in binary files. Use for symbol table extraction, import/export analysis, symbol renaming, or identifying library functions in ELF/Mach-O/PE binaries.
autoInvoke: false
---

# Symbol Analyzer — Binary Symbol Analysis

**Announce:** "Using rev-symbol skill — symbol analysis mode engaged."

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

## Commands by Format

### ELF (Linux)
```bash
readelf -s <binary>          # Symbol table
readelf --dyn-syms <binary>  # Dynamic symbols
readelf -r <binary>          # Relocation entries
nm -C <binary>               # Demangled symbols
objdump -T <binary>          # Dynamic symbol table
```

### Mach-O (macOS/iOS)
```bash
nm -g <binary>               # Global symbols
nm -m <binary>               # Mach-O specific format
otool -IV <binary>           # Import table
otool -tV <binary>           # Text section disassembly
```

### PE (Windows)
```bash
objdump -p <binary>          # PE headers
python3 -c "import pefile; pe=pefile.PE('<binary>'); pe.dump_info()"
```

### DEX (Android)
```bash
dexdump -l plain <file>.dex  # Class/method symbols
```

## Symbol Classification

| Symbol Type | Identification | Significance |
|-------------|---------------|-------------|
| **Exported (global)** | BIND_GLOBAL / STB_GLOBAL | Public API, hookable |
| **Imported** | NEEDED entries / imports | Dependencies, libraries |
| **Local (static)** | STB_LOCAL / BIND_LOCAL | Internal, not exported |
| **Weak** | STB_WEAK | Overridable, default impl |
| **Stripped** | Missing from symtab | Need recovery |
| **PLT/GOT** | .plt / .got sections | Indirect calls, hookable |

## Symbol Recovery for Stripped Binaries

### FLIRT Signature Matching
```bash
# IDA FLIRT signatures
# Apply signature files to identify known library functions
sigapply <binary> <sig_file>
```

### Pattern-Based Recovery
```python
# Match common function prologues
patterns = {
    "push_rbp": b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    "push_rbp_simple": b"\x55\x8b\xec",  # push rbp; mov ebp, esp (32-bit)
}

# Search binary for known patterns and suggest function names
```

### String-Based Recovery
```bash
# Find error strings → trace back to function → name function
strings -t x <binary> | grep -i "error\|fail\|invalid"
# Then cross-reference string addresses to find containing function
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
