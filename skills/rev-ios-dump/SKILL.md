---
name: rev-ios-dump
description: Activate when the user wants to dump or decrypt an iOS application (IPA) from a jailbroken device. Use for extracting decrypted iOS binaries, class-dump analysis, or iOS app reverse engineering with tools like frida-ios-dump, class-dump, or Clutch.
---

# iOS Dump — iOS Application Extraction & Analysis

**Announce:** "Using rev-ios-dump skill — iOS app dumping mode engaged."

> This is the lean entry point. For the full surface — every dump/extract command,
> the analysis-target matrix, and the post-dump analysis playbook — read
> [`reference.md`](references/reference.md) in this skill directory when you need it.

## Overview

Extract and analyze iOS applications from jailbroken devices. Dump decrypted binaries, extract class information, and analyze Objective-C/Swift runtime metadata.

**When to use:** the user wants a decrypted IPA, class-dump headers, or iOS app reverse engineering with `frida-ios-dump`, `class-dump`, or `Clutch`.

## Prerequisites (brief)

1. **Jailbroken iOS device** — confirm it is jailbroken
2. **SSH access** — `ssh root@<device_ip>` (default password: alpine)
3. **frida-ios-dump** — `pip3 install frida-tools` + frida-server on device
4. **class-dump** — macOS or `brew install class-dump`
5. **Clutch** or **bfdecrypt** — installed on device for decryption

## Execution Flow

```
User specifies iOS app to dump
      ↓
Verify device connection (SSH + frida)
      ↓
Dump decrypted IPA (frida-ios-dump / Clutch)
      ↓
Extract class metadata (class-dump)
      ↓
Analyze Objective-C/Swift headers
      ↓
Present findings
```

## Essential commands

The 90% path — dump, then class-dump. See [`reference.md`](references/reference.md) for Clutch,
Swift metadata, Info.plist, and the analysis-target matrix.

```bash
# Dump decrypted IPA with frida-ios-dump
frida-ios-dump -l                            # List installed apps
frida-ios-dump -o <output_dir> <bundle_id>   # Dump specific app

# Extract class headers from the decrypted binary
class-dump -H <decrypted_binary> -o <output_dir>
```

## Hard Rules

1. Always verify SSH connection before dumping
2. frida-server must match frida client version exactly
3. Change default SSH password (alpine) on jailbroken devices
4. Clean up dumped files on device after extraction
5. Respect app licensing — only dump apps user owns/has authorization to analyze

## Chain with other skills

`/rev-frida` (runtime hooking / dynamic iOS analysis) · `/rev-apkleaks` (secret patterns
adapted for iOS binaries) · `/rev-symbol` & `/rev-struct` (native framework analysis).

---
**Need more?** The full command catalog, analysis-target matrix, and post-dump analysis
playbook live in [`reference.md`](references/reference.md).
