---
name: rev-u3d-dump
description: Activate when the user wants to dump or extract Unity3D assets from a game or app. Use for extracting Unity DLLs (Assembly-CSharp.dll), asset bundles, shaders, textures, or game data from Unity3D applications on Android/iOS/PC.
---

# Unity3D Dump — Unity Asset Extraction

**Announce:** "Using rev-u3d-dump skill — Unity3D dump mode engaged."

> This is the lean entry point. For the full surface — every command variant, the
> analysis-target map, game-specific analysis, and the post-dump workflow — read
> [`reference.md`](references/reference.md) in this skill directory when you need it.

## Overview

Extract and analyze Unity3D game assets: managed DLLs (il2cpp), asset bundles, shaders, textures, scripts, and game data. Supports il2cpp dumping, AssetStudio extraction, and Unity runtime analysis.

## Prerequisites

1. **il2cppdumper** — For il2cpp binary → DLL reconstruction
2. **AssetStudio** or **AssetRipper** — For asset bundle extraction
3. **frida + frida-il2cpp-bridge** — For runtime il2cpp analysis
4. **Unity version identification** — From global-metadata.dat or libil2cpp.so

## Execution Flow

```
User provides Unity app (APK/IPA/PC)
      ↓
Identify Unity version and backend (Mono/il2cpp)
      ↓
If il2cpp: dump metadata → reconstruct DLLs
If Mono: extract DLLs directly
      ↓
Extract asset bundles (AssetStudio/AssetRipper)
      ↓
Analyze game logic in reconstructed DLLs
      ↓
Present findings
```

## Essential commands

Identify the Unity version and backend first — every later tool is version-sensitive.

```bash
# Identify Unity version + backend (Mono vs il2cpp)
strings libil2cpp.so | grep "Unity"
ls lib/armeabi-v7a/libil2cpp.so   # il2cpp present
ls lib/armeabi-v7a/libmono.so     # Mono present

# il2cpp: reconstruct DLLs from metadata
il2cppdumper libil2cpp.so global-metadata.dat <output_dir>
# Produces: DummyDll/ (reconstructed DLLs), script.json

# Mono: DLLs ship as-is inside the APK
unzip <game>.apk -d <output>      # assets/bin/Data/Managed/Assembly-CSharp.dll
```

See [`reference.md`](references/reference.md) for runtime (Frida) dumping, asset-bundle extraction,
the full analysis-target map, and game-specific / post-dump workflows.

## Hard Rules

1. il2cppdumper output is approximate — runtime dump (frida-il2cpp-bridge) is more accurate
2. Always identify Unity version first — tools are version-sensitive
3. il2cpp binaries change between Unity versions — match dumper version to game version
4. Asset bundles may be encrypted — check for

## Chain with other skills

`/rev-apkleaks` (API keys/tokens in the APK) · `/rev-frida` (runtime il2cpp hooking) ·
`/rev-symbol` & `/rev-struct` (native-library analysis). Use these to confirm or deepen findings.

---
**Need more?** The full command catalog, analysis-target map, game-specific analysis, and
post-dump workflow live in [`reference.md`](references/reference.md).
