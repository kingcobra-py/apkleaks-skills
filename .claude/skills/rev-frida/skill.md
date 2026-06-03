---
name: rev-frida
description: Activate when the user wants to dynamically instrument, hook, or trace functions in a running application using Frida. Use for runtime API interception, SSL pinning bypass, root detection bypass, or dynamic analysis of Android/iOS apps.
autoInvoke: false
---

# Frida — Dynamic Instrumentation Toolkit

**Announce:** "Using rev-frida skill — dynamic instrumentation mode engaged."

## Overview

Frida enables runtime function hooking, method tracing, and dynamic analysis of running applications. Inject JavaScript snippets into native functions or Java methods to intercept, modify, or observe behavior at runtime.

## Prerequisites

1. **frida + frida-tools** — `frida --version` (install: `pip3 install frida-tools`)
2. **frida-server** — Must be running on target device/emulator matching frida version
3. **USB debugging** — `adb devices` (for Android)
4. **Target app running** — Verify process is visible to Frida

## Setup frida-server on Android

```bash
# Download matching frida-server for device arch
adb shell getprop ro.product.cpu.abi  # arm64-v8a, armeabi-v7a, etc.

# Push and run frida-server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

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

## Common Commands

### List Running Processes
```bash
frida-ps -U
```

### List Installed Apps
```bash
frida-ps -Uai
```

### Attach to Process (Interactive REPL)
```bash
frida -U -n <package_name>
```

### Spawn with Script
```bash
frida -U -f <package_name> -l <script.js> --no-pause
```

### Trace Function Calls
```bash
frida-trace -U -f <package_name> -i "*open*" -i "*read*"
```

## Common Hook Patterns

### Hook Java Method
```javascript
Java.perform(function() {
  var TargetClass = Java.use("com.example.TargetClass");
  TargetClass.targetMethod.implementation = function(arg) {
    console.log("Hooked: targetMethod(" + arg + ")");
    var result = this.targetMethod(arg);
    console.log("Result: " + result);
    return result;
  };
});
```

### SSL Pinning Bypass
```javascript
Java.perform(function() {
  var SSLContext = Java.use("javax.net.ssl.SSLContext");
  SSLContext.init.overload("[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(tm, sr) {
    console.log("[+] SSL Pinning bypassed");
    this.init(Java.array("javax.net.ssl.TrustManager", [TrustManager.$new()]), null);
  };
});
```

### Root Detection Bypass
```javascript
Java.perform(function() {
  var RootCheck = Java.use("com.example.RootCheck");
  RootCheck.isRooted.implementation = function() {
    console.log("[+] Root check bypassed");
    return false;
  };
});
```

### Intercept Network Requests
```javascript
Java.perform(function() {
  var URL = Java.use("java.net.URL");
  URL.openConnection.overload().implementation = function() {
    console.log("[+] URL: " + this.toString());
    return this.openConnection();
  };
});
```

## Post-Hook Analysis

1. **Extract runtime values** — Hook getters/setters to capture dynamic secrets
2. **Trace call chains** — Use `frida-trace` to map function call sequences
3. **Dump memory** — Use `Memory.readByteArray()` for heap inspection
4. **Combine with static analysis** — Use `/rev-apkleaks` or `/rev-dex-dumper` for context

## Hard Rules

1. Always match frida-server version with frida client version
2. Never leave frida-server running after session — kill it when done
3. Hook scripts should have error handling — wrap in try-catch
4. For production apps, prefer spawn mode over attach mode
5. Clean up all injected hooks when analysis is complete
