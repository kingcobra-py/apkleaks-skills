---
name: rev-unicorn-debug
description: Activate when the user wants to emulate or debug CPU instructions using Unicorn Engine. Use for emulating specific functions, bypassing anti-analysis, solving CTF challenges, or debugging code without the original hardware. Supports ARM, x86, MIPS, and other architectures via Unicorn CPU emulator.
---

# Unicorn Debug — CPU Emulation & Debugging

**Announce:** "Using rev-unicorn-debug skill — CPU emulation mode engaged."

> This is the lean entry point. For the full surface — the complete emulation
> code catalog (function emulation, memory tracing, anti-debug bypass, CTF
> solver), the debugging-technique table, and post-emulation chaining — read
> [`reference.md`](references/reference.md) in this skill directory when you need it.

## Overview

Use Unicorn Engine to emulate CPU instructions without real hardware. Debug and trace execution of specific functions, bypass anti-analysis checks, solve CTF challenges, and analyze obfuscated code through CPU-level emulation.

## When to use

- Emulate a specific function in isolation (e.g. a key-validation or crypto routine).
- Bypass anti-analysis / anti-debug checks safely, off-device.
- Brute-force or solve CTF key checks by driving inputs through emulation.
- Trace execution or memory access when you lack the original hardware.

## Prerequisites

1. **unicorn** — `pip3 install unicorn` (CPU emulation engine)
2. **capstone** — `pip3 install capstone` (disassembly framework)
3. **Python 3** — For writing emulation scripts

## Supported Architectures

| Architecture | Unicorn Constant | Common Use |
|-------------|-----------------|------------|
| **ARM** | UC_ARCH_ARM | Android native, iOS |
| **ARM64** | UC_ARCH_ARM64 | Android 64-bit, iOS 64-bit |
| **x86** | UC_ARCH_X86 | Windows/Linux binaries |
| **MIPS** | UC_ARCH_MIPS | IoT firmware, routers |
| **RISC-V** | UC_ARCH_RISCV | Emerging IoT |

## Execution Flow

```
User provides binary code + architecture
      ↓
Set up Unicorn emulator (arch + mode)
      ↓
Map memory regions (code + stack + data)
      ↓
Write code bytes + setup registers
      ↓
Add hooks (instruction trace, memory access)
      ↓
Emulate execution
      ↓
Read results (registers + memory)
      ↓
Present findings
```

Concrete code for each step — basic function emulation, memory-access tracing,
anti-debug bypass, and CTF solving — lives in [`reference.md`](references/reference.md).

## Hard Rules

1. Always map enough stack memory — stack overflow causes cryptic Unicorn errors
2. Handle `UcError` exceptions — unmapped memory access is the most common error
3. Set correct architecture AND mode — ARM has both ARM and Thumb modes
4. Initialize all relevant registers before emulation — uninitialized registers cause unpredictable behavior
5. Verify emulation results against known test vectors when possible

## Chain with other skills

`/rev-frida` (verify emulation against runtime) · `/rev-struct` (data structures
being accessed) · `/rev-symbol` (resolve function addresses for emulation targets).

---
**Need more?** The full emulation pattern catalog, the debugging-technique table,
and the post-emulation chaining steps live in [`reference.md`](references/reference.md).
