---
name: rev-ios-dump
description: Activate when the user wants to dump or decrypt an iOS application (IPA) from a jailbroken device. Use for extracting decrypted iOS binaries, class-dump analysis, or iOS app reverse engineering with tools like frida-ios-dump, class-dump, or Clutch.
autoInvoke: false
---

# iOS Dump — iOS Application Extraction & Analysis

**Announce:** "Using rev-ios-dump skill — iOS app dumping mode engaged."

## Overview

Extract and analyze iOS applications from jailbroken devices. Dump decrypted binaries, extract class information, and analyze Objective-C/Swift runtime metadata.

## Prerequisites

1. **Jailbroken iOS device** — Check device is jailbroken
2. **SSH access** — `ssh root@<device_ip>` (default password: alpine)
3. **frida-ios-dump** — `pip3 install frida-tools` + frida-server on device
4. **class-dump** — Available on macOS or via Homebrew (`brew install class-dump`)
5. **Clutch** or **bfdecrypt** — Installed on jailbroken device for decryption

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

## Commands

### Dump IPA with frida-ios-dump
```bash
frida-ios-dump -l  # List installed apps
frida-ios-dump -o <output_dir> <bundle_id>  # Dump specific app
```

### Dump with Clutch (on device)
```bash
ssh root@<device_ip>
Clutch -i  # List encrypted apps
Clutch -d <bundle_id>  # Decrypt and dump
```

### Extract Class Information
```bash
class-dump -H <decrypted_binary> -o <output_dir>
```

### Analyze Swift Metadata
```bash
# Swift class analysis
class-dump -H <binary> -o <headers_dir>
grep -r "Swift" <headers_dir>/
```

### Extract Info.plist
```bash
plutil -p Info.plist  # macOS
# Or from dumped IPA
unzip <ipa_file> -d <extract_dir>
```

## Analysis Targets

| Target | Method | Output |
|--------|--------|--------|
| **Decrypted binary** | frida-ios-dump / Clutch | Executable for static analysis |
| **Class headers** | class-dump -H | .h files with declarations |
| **Protocol definitions** | class-dump + grep | Delegates, protocols |
| **URL schemes** | Info.plist | Custom URL handlers |
| **Entitlements** | codesign -d | App capabilities |
| **Frameworks** | Frameworks/ dir | Embedded libraries |

## Post-Dump Analysis

1. **Key classes** — Look for AuthManager, CryptoHelper, NetworkClient, Config classes
2. **Protocol handlers** — Check URL schemes for deep-link vulnerabilities
3. **Entitlements** — Identify excessive permissions
4. **Secret scanning** — Use `/rev-apkleaks` patterns adapted for iOS binaries
5. **Runtime hooking** — Use `/rev-frida` for dynamic iOS analysis

## Hard Rules

1. Always verify SSH connection before dumping
2. frida-server must match frida client version exactly
3. Change default SSH password (alpine) on jailbroken devices
4. Clean up dumped files on device after extraction
5. Respect app licensing — only dump apps user owns/has authorization to analyze
