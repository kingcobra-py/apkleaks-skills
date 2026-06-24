---
name: rev-frida
description: Activate when the user wants to dynamically instrument, hook, or trace functions in a running application using Frida. Use for runtime API interception, SSL pinning bypass, root detection bypass, or dynamic analysis of Android/iOS apps.
---

# Frida — Dynamic Instrumentation Toolkit

**Announce:** "Using rev-frida skill — dynamic instrumentation mode engaged."

> This is the lean entry point. For the full surface — frida-server setup on
> Android, the complete command catalog, and the full library of hook scripts
> (Java method, SSL pinning bypass, root detection bypass, network intercept) —
> read [`reference.md`](references/reference.md) in this skill directory when you need it.

## Overview

Frida enables runtime function hooking, method tracing, and dynamic analysis of running applications. Inject JavaScript snippets into native functions or Java methods to intercept, modify, or observe behavior at runtime.

Use it when static analysis is not enough: to capture dynamic secrets, bypass SSL pinning or root detection, or confirm a static finding actually fires at runtime.

## Prerequisites (quick check)

1. **frida + frida-tools** — `frida --version` (install: `pip3 install frida-tools`)
2. **frida-server** — running on the target device, version matching the client
3. **USB debugging** — `adb devices` (for Android)
4. **Target app** — process visible to Frida

Full device-side setup (download by arch, push, run) lives in [`reference.md`](references/reference.md).

## Execution Flow

```
User specifies target app + hook target
      ↓
Verify frida-server running on device
      ↓
List processes: frida-ps -U
      ↓
Attach or spawn target app
      ↓
Inject JavaScript hook script
      ↓
Collect and present intercepted data
```

## Essential commands

```bash
# Discover targets
frida-ps -U                                          # running processes
frida-ps -Uai                                        # installed apps

# Attach (interactive REPL) or spawn with a script
frida -U -n <package_name>
frida -U -f <package_name> -l <script.js> --no-pause # spawn mode (preferred)

# Trace function calls
frida-trace -U -f <package_name> -i "*open*" -i "*read*"
```

Hook script templates (Java method, SSL pinning bypass, root detection bypass, network intercept) and the full command catalog are in [`reference.md`](references/reference.md).

## Hard Rules

1. Always match frida-server version with frida client version
2. Never leave frida-server running after session — kill it when done
3. Hook scripts should have error handling — wrap in try-catch
4. For production apps, prefer spawn mode over attach mode
5. Clean up all injected hooks when analysis is complete

## Chain with other skills

`/rev-apkleaks` & `/rev-dex-dumper` give static context for choosing hook targets;
Frida confirms or deepens those findings at runtime.

---
**Need more?** frida-server device setup, the full command catalog, the hook-pattern
library, and post-hook analysis depth live in [`reference.md`](references/reference.md).
