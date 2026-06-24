# rev-ios-dump — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path — dump then class-dump;
> come here for the full command catalog, the analysis-target matrix, and the
> post-dump analysis playbook.

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
