---
name: rev-idapython
description: Activate when the user wants to write IDA Pro Python scripts for binary analysis, disassembly scripting, or automated reverse engineering tasks in IDA. Use for IDAPython scripting, plugin development, or batch analysis of binary files in IDA Pro.
autoInvoke: false
---

# IDAPython — IDA Pro Python Scripting

**Announce:** "Using rev-idapython skill — IDA Pro scripting mode engaged."

## Overview

IDAPython provides Python scripting access to IDA Pro's disassembly and analysis engine. Automate function identification, string extraction, cross-reference analysis, pattern searching, and batch binary analysis.

## Key IDAPython Modules

| Module | Purpose |
|--------|---------|
| `idaapi` | Core IDA API — database, UI, events |
| `idautils` | Utility functions — functions, refs, searches |
| `idc` | IDA Commands — simple wrappers for common operations |
| `ida_bytes` | Byte-level operations — read, write, patch |
| `ida_funcs` | Function management — create, delete, iterate |
| `ida_name` | Name management — get, set, iterate names |
| `ida_xref` | Cross-reference operations |
| `ida_search` | Search operations — text, binary, regex |

## Common Script Patterns

### List All Functions
```python
import idautils
for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    print(f"0x{func_ea:x}: {func_name}")
```

### Extract All Strings
```python
import idautils
for s in idautils.Strings():
    print(f"0x{s.ea:x}: {str(s)}")
```

### Find Cross-References to Address
```python
import idautils
target_ea = 0x1000  # target address
for xref in idautils.XrefsTo(target_ea):
    print(f"Ref from 0x{xref.frm:x} (type={xref.type})")
```

### Rename Functions by Pattern
```python
import idc, idautils
import re

for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if re.match(r"sub_[0-9A-F]+", name):
        # Analyze function to suggest meaningful name
        idc.set_name(func_ea, "analyzed_" + name, idc.SN_NOWARN)
```

### Find Crypto Constants
```python
import ida_bytes, idautils
import struct

AES_SBOX = [0x63, 0x7c, 0x77, 0x7b]  # partial S-box
for seg_ea in idautils.Segments():
    for ea in idautils.Functions():
        # Search for crypto constants in function bytes
        data = ida_bytes.get_bytes(ea, 256)
        if data and any(b in data for b in AES_SBOX):
            print(f"Possible crypto at 0x{ea:x}")
```

### Batch Function Analysis
```python
import idautils, idc, ida_funcs

results = []
for func_ea in idautils.Functions():
    func = ida_funcs.get_func(func_ea)
    if func:
        size = func.size()
        name = idc.get_func_name(func_ea)
        results.append((func_ea, name, size))

# Sort by size — large functions are often important
results.sort(key=lambda x: x[2], reverse=True)
for ea, name, size in results[:20]:
    print(f"0x{ea:x}: {name} (size={size})")
```

## Post-Script Analysis

1. **Export results** — Write analysis data to JSON/CSV for further processing
2. **Annotate IDA database** — Use `idc.set_name()`, `idc.set_comment()` to mark findings
3. **Combine with dynamic analysis** — Use `/rev-frida` to verify static findings at runtime
4. **Combine with DEX analysis** — Use `/rev-dex-dumper` for Android-specific context

## Hard Rules

1. Always use `idaapi.auto_wait()` before reading analysis results
2. Scripts should handle None returns from IDA API — many functions return None on error
3. Use `idc.get_func_name()` not `idc.GetFunctionName()` — new API preferred
4. Batch scripts should use `idaapi.msg()` for output in IDA console
5. Never modify IDA database without user confirmation — use `idc.set_name()` with SN_NOWARN only for obvious cases