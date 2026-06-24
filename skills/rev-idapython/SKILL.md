---
name: rev-idapython
description: Activate when the user wants to write IDA Pro Python scripts for binary analysis, disassembly scripting, or automated reverse engineering tasks in IDA. Use for IDAPython scripting, plugin development, or batch analysis of binary files in IDA Pro.
---

# IDAPython — IDA Pro Python Scripting

**Announce:** "Using rev-idapython skill — IDA Pro scripting mode engaged."

> This is the lean entry point. For the full surface — the complete script-pattern
> catalog (list functions, extract strings, xrefs, rename, crypto constants, batch
> analysis) and the post-script depth — read [`reference.md`](references/reference.md) in this
> skill directory when you need it.

## Overview

IDAPython provides Python scripting access to IDA Pro's disassembly and analysis engine. Automate function identification, string extraction, cross-reference analysis, pattern searching, and batch binary analysis.

## When to use

Reach for this skill when the user wants to script IDA Pro: enumerate functions, extract strings, trace cross-references, rename symbols in bulk, hunt for crypto constants, or run batch analysis over a binary database.

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

## Workflow

1. **Wait for analysis** — call `idaapi.auto_wait()` before reading results.
2. **Enumerate** — iterate `idautils.Functions()` / `idautils.Strings()` to build a picture.
3. **Pivot** — follow cross-references (`idautils.XrefsTo`) to the code that matters.
4. **Annotate or export** — rename with `idc.set_name()`, comment, or dump to JSON/CSV.
5. **Verify** — chain to `/rev-frida` (runtime) or `/rev-dex-dumper` (Android) to confirm.

See [`reference.md`](references/reference.md) for ready-to-run scripts covering each step.

## Hard Rules

1. Always use `idaapi.auto_wait()` before reading analysis results
2. Scripts should handle None returns from IDA API — many functions return None on error
3. Use `idc.get_func_name()` not `idc.GetFunctionName()` — new API preferred
4. Batch scripts should use `idaapi.msg()` for output in IDA console
5. Never modify IDA database without user confirmation — use `idc.set_name()` with SN_NOWARN only for obvious cases

## Chain with other skills

`/rev-frida` (verify static analysis against runtime) · `/rev-struct` (reconstruct data
structures you find) · `/rev-symbol` (resolve imports/exports) · `/rev-unicorn-debug`
(emulate a function isolated in IDA).

---
**Need more?** The full script-pattern catalog and post-script analysis steps live in
[`reference.md`](references/reference.md).
