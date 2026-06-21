# Setup Guide: Dependencies for iOS Reverse Engineering

## Xcode Command Line Tools (otool, strings, codesign, lipo, nm)

Most analysis tools are included with Xcode Command Line Tools on macOS.

### macOS

```bash
xcode-select --install
```

### Verify

```bash
otool --version
strings --version
codesign --help
```

### Linux

`otool`/`codesign`/`plutil`/`PlistBuddy`/`lipo` are macOS-only — **but the skill does not require
them on Linux.** The scripts auto-fallback to cross-platform equivalents:

| macOS-only tool | Linux / cross-platform fallback used by the skill |
|---|---|
| `otool -L/-l/-oV/-hv` | `ipsw macho info -l/-o/-d` (linked libs, load commands, objc, flags) |
| `codesign` / `jtool2` (entitlements) | `ipsw macho info -e` |
| `lipo -info/-thin` | `ipsw macho info` arch line / `ipsw macho lipo --arch <arch>` |
| `nm` | `nm` from **binutils** (often present on Linux); `ipsw macho info -n` otherwise |
| `plutil` / `PlistBuddy` | `python3` plistlib (binary-plist capable) or `plistutil` (**libplist**) |

So on Linux install **`ipsw`** (the cross-platform backbone), **`binutils`** (`strings`/`nm`),
and a plist reader (**`libplist-utils`** or just **`python3`**):

```bash
# Debian/Ubuntu
sudo apt-get install binutils libplist-utils
# ipsw from GitHub releases (see the ipsw section below)
curl -LO https://github.com/blacktop/ipsw/releases/latest/download/ipsw_Linux_x86_64.tar.gz
tar xzf ipsw_Linux_x86_64.tar.gz && mv ipsw ~/.local/bin/

# Arch
sudo pacman -S binutils libplist
# Fedora
sudo dnf install binutils libplist
```

Or let the installer handle it: `scripts/install-dep.sh xcode-cli-tools` installs `binutils` +
`libplist` on Linux, and `scripts/install-dep.sh libplist` installs just the plist reader.

> **Tip**: `check-deps.sh` exits 0 on Linux once `ipsw` + `strings` + a plist reader are present;
> `otool`/`codesign`/`lipo` are reported as `INSTALL_OPTIONAL`, not required.

---

## ipsw (primary tool — includes class-dump)

`ipsw` (blacktop/ipsw) is a comprehensive iOS/macOS research toolkit that includes class-dump functionality, dyld shared cache analysis, Mach-O inspection, and much more. It replaces the legacy `class-dump` tool with better Swift support and active maintenance.

### Option 1: Homebrew (recommended)

```bash
brew install blacktop/tap/ipsw
```

### Option 2: Download from GitHub releases

Download the latest release for your platform from:
https://github.com/blacktop/ipsw/releases

```bash
# macOS arm64 example
curl -LO https://github.com/blacktop/ipsw/releases/latest/download/ipsw_macOS_arm64.tar.gz
tar xzf ipsw_macOS_arm64.tar.gz
mv ipsw /usr/local/bin/
```

### Verify

```bash
ipsw version
```

### Key features

- **class-dump**: Extract Objective-C and Swift headers (`ipsw class-dump`)
- **dyld shared cache**: Analyze and extract from dyld shared caches (`ipsw dyld`)
- **Mach-O analysis**: Inspect segments, symbols, imports, ObjC metadata (`ipsw macho`)
- **Disassembly**: Disassemble functions and symbols (`ipsw disass`)
- **IPSW firmware**: Download and analyze iOS firmware files (`ipsw download`)

### Limitations

- **Encrypted binaries**: Cannot process encrypted (FairPlay DRM) binaries. Decrypt first (e.g., via `frida-ios-dump`, `Clutch`, or `bfdecrypt` on a jailbroken device).
- **Pure Swift apps**: While ipsw has better Swift support than legacy class-dump, some pure Swift types may not appear. Use `nm` + `swift-demangle` for full symbol analysis.

---

## jtool2 (optional, recommended)

jtool2 is a comprehensive Mach-O analyzer, replacement for otool, nm, and codesign.

### Download

```bash
# Download from the official source
curl -o jtool2.tgz http://www.newosxbook.com/tools/jtool2.tgz
mkdir -p ~/jtool2
tar xzf jtool2.tgz -C ~/jtool2
cp ~/jtool2/jtool2 /usr/local/bin/
```

### Verify

```bash
jtool2 --help
```

### Key features over otool

- Color-coded output
- Better symbol resolution
- Entitlements extraction
- Code signature analysis
- Disassembly with symbolic references

---

## Frida (optional)

Frida is a dynamic instrumentation toolkit for runtime analysis of iOS apps.

### Install

```bash
pip3 install frida-tools
```

### Verify

```bash
frida --version
```

### Usage for iOS

Requires a jailbroken device with `frida-server` running, or a repackaged app with `FridaGadget.dylib`:

```bash
# List running processes on USB device
frida-ps -U

# Attach to an app
frida -U com.example.app

# Run a script
frida -U -f com.example.app -l hook-script.js
```

---

## libimobiledevice (optional)

Tools for communicating with iOS devices without iTunes/Finder.

### macOS

```bash
brew install libimobiledevice ideviceinstaller
```

### Linux

```bash
# Ubuntu/Debian
sudo apt install libimobiledevice-utils ideviceinstaller

# Fedora
sudo dnf install libimobiledevice-utils
```

### Verify

```bash
ideviceinfo --help
```

### Useful commands

```bash
# Get device info
ideviceinfo

# List installed apps
ideviceinstaller -l

# Install an IPA
ideviceinstaller -i app.ipa

# Pull crash logs
idevicecrashreport -e ./crashlogs/
```

---

## Optional Tools

### swift-demangle

Demangles Swift symbols to human-readable names. Included with the Swift toolchain.

```bash
# macOS (included with Xcode)
swift demangle '_$s7MyClass4nameSSvg'
# Output: MyClass.name.getter

# Or pipe symbols
nm binary | swift demangle
```

### dsdump (modern class-dump alternative)

Better support for Swift and modern Objective-C:

```bash
brew install DerekSelander/brew/dsdump

# Dump Swift classes
dsdump --swift MyApp

# Dump Objective-C classes
dsdump --objc MyApp
```

### radare2 / rizin

Open-source reverse engineering framework:

```bash
brew install radare2
# Or the modern fork:
brew install rizin

# Analyze a binary
r2 MyApp
# or
rizin MyApp
```

### Ghidra

NSA's open-source reverse engineering suite with iOS support:

1. Download from https://ghidra-sre.org/
2. Extract and run
3. Import the Mach-O binary
4. Auto-analyze

Ghidra provides full decompilation to C-like pseudocode, which is invaluable for complex analysis.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ipsw: command not found` | Install via `brew install blacktop/tap/ipsw` or add to PATH |
| ipsw class-dump outputs nothing | Binary may be encrypted (FairPlay). Decrypt first on jailbroken device |
| ipsw class-dump limited Swift output | Use `dsdump --swift` or `nm` + `swift-demangle` for deeper analysis |
| `otool: command not found` | Install Xcode Command Line Tools: `xcode-select --install` (macOS). On Linux this is expected — the scripts fall back to `ipsw macho info` automatically |
| Fat binary issues | Use `lipo -thin arm64 binary -output binary-arm64` to extract one arch |
| `ipsw macho info` prompts for architecture (hangs) | It opens an interactive TUI on fat/universal binaries. Pass `--arch arm64` (or thin first); the skill's scripts already pass `--arch` automatically |
| Encrypted IPA from App Store | Must decrypt on jailbroken device or use `frida-ios-dump` |
| `codesign` permission denied | May need to run with `sudo` or adjust entitlements |
| jtool2 won't run on macOS | Right-click → Open, or `xattr -d com.apple.quarantine jtool2` |
| Frida can't find device | Ensure `frida-server` is running on jailbroken device, or use `frida-gadget` |
| IPA won't unzip | Rename to `.zip` and try again, or use `7z x app.ipa` |
