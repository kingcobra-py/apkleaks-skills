# rev-u3d-dump — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full surface: every command variant, the analysis-target map, game-specific
> analysis, and the post-dump workflow.

## Commands

### Identify Unity Version
```bash
# Android: check libil2cpp.so or global-metadata.dat
strings libil2cpp.so | grep "Unity"
strings global-metadata.dat | head -20

# Check for Mono vs il2cpp
ls lib/armeabi-v7a/libil2cpp.so  # il2cpp
ls lib/armeabi-v7a/libmono.so   # Mono
```

### il2cpp Dump (Android)
```bash
# Extract from APK
apktool d <game>.apk -o <output>

# Run il2cppdumper
il2cppdumper libil2cpp.so global-metadata.dat <output_dir>
# Produces: DummyDll/ (reconstructed DLLs), script.json (metadata)
```

### il2cpp Runtime Dump (Frida)
```bash
# Use frida-il2cpp-bridge for runtime dumping
frida -U -f <package_name> -l il2cpp_bridge.js --no-pause
# Dumps accurate method offsets and class info at runtime
```

### Mono DLL Extraction
```bash
# Mono DLLs are in the APK as-is
unzip <game>.apk -d <output>
ls <output>/assets/bin/Data/Managed/  # DLLs here
# Key file: Assembly-CSharp.dll
```

### Asset Bundle Extraction
```bash
# Using AssetStudio (GUI)
# Open APK/IPA → load all asset bundles → export selected assets

# Using AssetRipper (CLI)
AssetRipper <game.apk> -o <output_dir>
```

## Analysis Targets

| Target | Location | Tool |
|--------|----------|------|
| **Game logic DLLs** | Assembly-CSharp.dll | dnSpy / ILSpy |
| **il2cpp metadata** | global-metadata.dat | il2cppdumper |
| **Asset bundles** | assets/bin/Data/ | AssetStudio |
| **Shaders** | bundle files | AssetStudio |
| **Textures/Sprites** | bundle files | AssetStudio |
| **Audio clips** | bundle files | AssetStudio |
| **Scene data** | level files | AssetRipper |
| **Player prefs** | SharedPreferences / NSUserDefaults | Manual |

## Game-Specific Analysis

### Find Game Logic Classes
```bash
# In reconstructed DLL, search for:
# - GameManager, LevelManager, PlayerController
# - CurrencyManager, ShopManager, IAPManager
# - NetworkManager, APIManager, AuthManager
```

### Analyze Anti-Cheat
```bash
# Look for:
# - Integrity check functions
# - Hash verification
# - Server-side validation calls
# - Root/jailbreak detection
```

## Post-Dump Analysis

1. **Decompile DLLs** — Use dnSpy (Windows) or ILSpy for C# decompilation
2. **Find secrets** — Use `/rev-apkleaks` on the APK for API keys/tokens
3. **Hook game functions** — Use `/rev-frida` with il2cpp bridge for runtime manipulation
4. **Analyze networking** — Look for API endpoints in game logic classes
