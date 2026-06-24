---
name: rev-struct
description: Reconstruct data structures by analyzing memory access patterns across functions. Activate when the user wants to reverse-engineer struct/class layouts, identify field offsets, or reconstruct data types from binary analysis. Use for C struct reconstruction, VTable analysis, or memory layout recovery.
---

# Struct Reconstructor — Data Structure Recovery

**Announce:** "Using rev-struct skill — structure reconstruction mode engaged."

> This is the lean entry point. For the full surface — the worked IDAPython
> collectors, the VTable extractor, the cross-reference validator, and the
> post-reconstruction workflow — read [`reference.md`](references/reference.md) in this skill
> directory when you need it.

## Overview

Reconstruct data structures by analyzing memory access patterns in disassembled/decompiled code. Identify struct layouts, field offsets, sizes, and types from how functions access memory through pointers.

## When to use

- Reverse-engineering C `struct` or C++ class layouts from a binary
- Identifying field offsets, sizes, and inferred types
- Recovering memory layout when no symbols/headers are available
- VTable analysis for C++ classes with virtual functions

## Methodology at a glance

Four phases — see [`reference.md`](references/reference.md) for the code behind each:

1. **Identify structure candidates** — find pointers accessed at multiple consistent offsets (`[reg + offset]`), single-pointer args, `malloc`/`calloc` followed by offset-based init.
2. **Collect offset accesses** — for each candidate, record every offset touched across the function (IDAPython `collect_offsets`).
3. **Determine field types** — infer type/size from the access instruction (`mov` → int/ptr, `movsd` → double, `movss` → float, `cmp byte` → bool, `lea` → sub-struct, string fns → `char*`).
4. **Reconstruct the struct definition** — lay out fields with offsets, types, and alignment padding into a C `struct`.

Then **VTable analysis** (extract virtual function pointers) and **cross-reference validation** (confirm the layout holds across every function that touches the struct). Full code, the access-pattern → type table, and the post-reconstruction steps (define in IDA, apply, export `.h`, validate dynamically) are in [`reference.md`](references/reference.md).

## Hard Rules

1. Always validate struct layout across multiple functions — single function may not access all fields
2. Account for alignment padding — compilers insert padding between fields
3. Distinguish between base class and derived class fields in C++ structs
4. VTable pointer is always at offset 0x0 in C++ objects with virtual methods
5. Document confidence level for each field type inference

## Chain with other skills

`/rev-frida` (verify struct layout at runtime) · `/rev-symbol` (named references for fields/methods) · `/rev-idapython` (scripting the collectors below) · `/rev-unicorn-debug` (emulate to observe access).

---
**Need more?** The full IDAPython collectors, VTable extractor, cross-reference
validator, the access-pattern type table, and the post-reconstruction workflow
live in [`reference.md`](references/reference.md).
