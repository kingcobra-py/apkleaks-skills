# rev-idapython — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full surface: the complete script-pattern catalog and the post-script depth
> (export, annotation, and cross-skill verification).

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
