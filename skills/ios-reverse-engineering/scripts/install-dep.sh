#!/usr/bin/env bash
# install-dep.sh — Install a single dependency for iOS reverse engineering
# Usage: install-dep.sh <dependency>
#
# Exit codes:
#   0 — installed successfully
#   1 — installation failed
#   2 — requires manual action (e.g. sudo needed but not available)
set -euo pipefail

usage() {
  cat <<EOF
Usage: install-dep.sh <dependency>

Install a dependency required for iOS reverse engineering.

Available dependencies:
  ipsw              ipsw toolkit (includes class-dump, dyld cache analysis, and more)
  xcode-cli-tools   Xcode Command Line Tools (otool, strings, codesign, lipo, nm) — macOS
  libplist          libplist / plistutil (cross-platform plist reader, Linux alternative to plutil)
  jtool2            jtool2 Mach-O analyzer
  frida             Frida dynamic instrumentation toolkit
  libimobiledevice  Tools for iOS device interaction
  swift-demangle    Swift symbol demangler
  radare2           radare2 reverse engineering framework (deep binary analysis)
  rizin             rizin reverse engineering framework (radare2 fork)
  ghidra            Ghidra headless analyzer (NSA's RE tool, decompilation)

The script detects your OS and package manager, then:
  - Installs directly if possible (brew, or user-local install)
  - Uses sudo if available and needed
  - Prints manual instructions if neither option works
EOF
  exit 0
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
fi

DEP="$1"

# --- Detect environment ---
OS="unknown"
PKG_MANAGER="none"
HAS_SUDO=false
ARCH=$(uname -m)

case "$(uname -s)" in
  Linux)  OS="linux" ;;
  Darwin) OS="macos" ;;
esac

# Detect package manager
if command -v brew &>/dev/null; then
  PKG_MANAGER="brew"
elif command -v apt-get &>/dev/null; then
  PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
elif command -v pacman &>/dev/null; then
  PKG_MANAGER="pacman"
fi

# Check sudo availability
if command -v sudo &>/dev/null; then
  if sudo -n true 2>/dev/null; then
    HAS_SUDO=true
  else
    HAS_SUDO=true
  fi
fi

info()  { echo "[INFO] $*"; }
ok()    { echo "[OK] $*"; }
fail()  { echo "[FAIL] $*" >&2; }
manual() {
  echo "[MANUAL] $*" >&2
  echo "         Cannot install automatically. Please install manually and retry." >&2
  exit 2
}

# --- Helper: install via system package manager ---
pkg_install() {
  local pkg="$1"
  case "$PKG_MANAGER" in
    brew)
      info "Installing $pkg via Homebrew..."
      brew install "$pkg"
      ;;
    apt)
      if [[ "$HAS_SUDO" == true ]]; then
        info "Installing $pkg via apt..."
        sudo apt-get update -qq && sudo apt-get install -y -qq "$pkg"
      else
        manual "Run: sudo apt-get install $pkg"
      fi
      ;;
    dnf)
      if [[ "$HAS_SUDO" == true ]]; then
        info "Installing $pkg via dnf..."
        sudo dnf install -y "$pkg"
      else
        manual "Run: sudo dnf install $pkg"
      fi
      ;;
    pacman)
      if [[ "$HAS_SUDO" == true ]]; then
        info "Installing $pkg via pacman..."
        sudo pacman -S --noconfirm "$pkg"
      else
        manual "Run: sudo pacman -S $pkg"
      fi
      ;;
    *)
      manual "No supported package manager found. Install $pkg manually."
      ;;
  esac
}

# --- Helper: download a file ---
download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL -o "$dest" "$url"
  elif command -v wget &>/dev/null; then
    wget -q -O "$dest" "$url"
  else
    fail "Neither curl nor wget available."
    return 1
  fi
}

# --- Helper: get latest GitHub release tag ---
gh_latest_tag() {
  local repo="$1"
  local url="https://api.github.com/repos/$repo/releases/latest"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/'
  elif command -v wget &>/dev/null; then
    wget -q -O - "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/'
  fi
}

# --- Helper: add a line to shell profile if not already present ---
add_to_profile() {
  local line="$1"
  local profile=""
  if [[ -f "$HOME/.zshrc" ]]; then
    profile="$HOME/.zshrc"
  elif [[ -f "$HOME/.bashrc" ]]; then
    profile="$HOME/.bashrc"
  elif [[ -f "$HOME/.profile" ]]; then
    profile="$HOME/.profile"
  fi

  if [[ -n "$profile" ]]; then
    if ! grep -qF "$line" "$profile" 2>/dev/null; then
      echo "$line" >> "$profile"
      info "Added to $profile: $line"
      info "Run 'source $profile' or start a new shell to apply."
    fi
  else
    info "Add this to your shell profile: $line"
  fi
}

# =====================================================================
# Dependency installers
# =====================================================================

install_ipsw() {
  if command -v ipsw &>/dev/null; then
    ok "ipsw already installed"
    return 0
  fi

  # Try brew first (recommended)
  if [[ "$PKG_MANAGER" == "brew" ]]; then
    info "Installing ipsw via Homebrew..."
    if brew install blacktop/tap/ipsw 2>/dev/null; then
      ok "ipsw installed via Homebrew"
      return 0
    fi
    info "Homebrew tap install failed, falling back to direct download."
  fi

  # Download from GitHub releases
  info "Installing ipsw from GitHub releases..."
  local tag
  tag=$(gh_latest_tag "blacktop/ipsw" 2>/dev/null || echo "")

  if [[ -z "$tag" ]]; then
    manual "Install ipsw via: brew install blacktop/tap/ipsw\nOr download from https://github.com/blacktop/ipsw/releases"
  fi

  local install_dir="$HOME/.local/share/ipsw"
  mkdir -p "$install_dir"
  mkdir -p "$HOME/.local/bin"

  # Determine platform and architecture for download
  local platform=""
  local arch_suffix=""
  case "$OS" in
    macos)  platform="macOS" ;;
    linux)  platform="Linux" ;;
  esac
  case "$ARCH" in
    x86_64)  arch_suffix="x86_64" ;;
    arm64|aarch64)  arch_suffix="arm64" ;;
  esac

  local filename="ipsw_${tag#v}_${platform}_${arch_suffix}"
  local url="https://github.com/blacktop/ipsw/releases/download/${tag}/${filename}.tar.gz"
  local tmp_file
  tmp_file=$(mktemp "${TMPDIR:-/tmp}/ipsw-XXXXXX.tar.gz")

  info "Downloading ipsw $tag for ${platform}/${arch_suffix}..."
  if download "$url" "$tmp_file"; then
    tar xzf "$tmp_file" -C "$install_dir" 2>/dev/null
    rm -f "$tmp_file"
    if [[ -f "$install_dir/ipsw" ]]; then
      chmod +x "$install_dir/ipsw"
      ln -sf "$install_dir/ipsw" "$HOME/.local/bin/ipsw"
      export PATH="$HOME/.local/bin:$PATH"
      add_to_profile 'export PATH="$HOME/.local/bin:$PATH"'
      ok "ipsw $tag installed"
      return 0
    fi
  fi
  rm -f "$tmp_file"

  manual "Install ipsw via: brew install blacktop/tap/ipsw\nOr download from https://github.com/blacktop/ipsw/releases"
}

install_xcode_cli_tools() {
  if command -v otool &>/dev/null && command -v strings &>/dev/null; then
    ok "Xcode Command Line Tools already installed"
    return 0
  fi

  if [[ "$OS" == "macos" ]]; then
    info "Installing Xcode Command Line Tools..."
    xcode-select --install 2>/dev/null || true
    echo "Xcode Command Line Tools installation triggered."
    echo "Please complete the installation dialog and re-run the dependency check."
    exit 0
  else
    # Linux: install binutils (strings/nm) and libplist (plistutil) for cross-platform analysis.
    # otool/codesign/lipo/plutil are macOS-only; the scripts fall back to `ipsw macho info` for
    # Mach-O analysis and to python3 plistlib / plistutil for plists.
    info "Installing binutils (provides strings/nm) on Linux..."
    case "$PKG_MANAGER" in
      apt)     pkg_install "binutils" ;;
      dnf)     pkg_install "binutils" ;;
      pacman)  pkg_install "binutils" ;;
      brew)    pkg_install "binutils" ;;
      *)       manual "Install binutils for 'strings'/'nm' commands" ;;
    esac
    ok "binutils installed"
    info "Installing libplist (provides plistutil) on Linux..."
    install_libplist
    info "Note: otool/codesign/lipo/plutil are macOS-only. The scripts use 'ipsw macho info' for Mach-O analysis and python3/plistutil for plists on Linux."
  fi
}

install_libplist() {
  if command -v plistutil &>/dev/null; then
    ok "libplist (plistutil) already installed"
    return 0
  fi
  # python3 plistlib is an acceptable cross-platform alternative (lib/plist.sh falls back to it).
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import plistlib' 2>/dev/null; then
    ok "python3 plistlib available (plist reader present — libplist optional)"
    return 0
  fi

  case "$PKG_MANAGER" in
    apt)     pkg_install "libplist-utils" ;;   # Debian: plistutil is in libplist-utils
    dnf)     pkg_install "libplist" ;;
    pacman)  pkg_install "libplist" ;;
    brew)    pkg_install "libplist" ;;
    *)       manual "Install libplist (provides 'plistutil') or python3" ;;
  esac
  ok "libplist installed"
}

install_jtool2() {
  if command -v jtool2 &>/dev/null || command -v jtool &>/dev/null; then
    ok "jtool2 already installed"
    return 0
  fi

  if [[ "$OS" == "macos" ]]; then
    info "jtool2 must be downloaded manually from http://www.newosxbook.com/tools/jtool2.tgz"
    local install_dir="$HOME/.local/share/jtool2"
    local tmp_file
    tmp_file=$(mktemp "${TMPDIR:-/tmp}/jtool2-XXXXXX.tgz")

    info "Downloading jtool2..."
    if download "http://www.newosxbook.com/tools/jtool2.tgz" "$tmp_file"; then
      mkdir -p "$install_dir"
      tar xzf "$tmp_file" -C "$install_dir"
      rm -f "$tmp_file"
      mkdir -p "$HOME/.local/bin"
      if [[ -f "$install_dir/jtool2" ]]; then
        chmod +x "$install_dir/jtool2"
        ln -sf "$install_dir/jtool2" "$HOME/.local/bin/jtool2"
      fi
      export PATH="$HOME/.local/bin:$PATH"
      add_to_profile 'export PATH="$HOME/.local/bin:$PATH"'
      ok "jtool2 installed to $install_dir"
    else
      manual "Download jtool2 from http://www.newosxbook.com/tools/jtool2.tgz"
    fi
  else
    manual "jtool2 is primarily a macOS tool. Download from http://www.newosxbook.com/tools/jtool2.tgz"
  fi
}

install_frida() {
  if command -v frida &>/dev/null; then
    ok "frida already installed"
    return 0
  fi

  if command -v pip3 &>/dev/null; then
    info "Installing frida-tools via pip3..."
    pip3 install frida-tools
    ok "frida-tools installed"
  elif command -v pip &>/dev/null; then
    info "Installing frida-tools via pip..."
    pip install frida-tools
    ok "frida-tools installed"
  else
    manual "Install Python/pip first, then run: pip3 install frida-tools"
  fi
}

install_libimobiledevice() {
  if command -v ideviceinstaller &>/dev/null || command -v ideviceinfo &>/dev/null; then
    ok "libimobiledevice already installed"
    return 0
  fi

  case "$PKG_MANAGER" in
    brew)    pkg_install "libimobiledevice"; pkg_install "ideviceinstaller" ;;
    apt)     pkg_install "libimobiledevice-utils" ;;
    dnf)     pkg_install "libimobiledevice-utils" ;;
    pacman)  pkg_install "libimobiledevice" ;;
    *)       manual "Install libimobiledevice from https://libimobiledevice.org/" ;;
  esac

  ok "libimobiledevice installed"
}

install_swift_demangle() {
  if command -v swift-demangle &>/dev/null || command -v swift &>/dev/null; then
    ok "swift-demangle already available"
    return 0
  fi

  if [[ "$OS" == "macos" ]]; then
    info "swift-demangle is included with Xcode. Install Xcode or Xcode Command Line Tools."
    xcode-select --install 2>/dev/null || true
    exit 0
  else
    manual "Install Swift from https://swift.org/download/ to get swift-demangle"
  fi
}

# =====================================================================
# Dispatch
# =====================================================================

install_radare2() {
  if command -v r2 &>/dev/null || command -v radare2 &>/dev/null; then
    ok "radare2 already installed"
    return 0
  fi

  case "$PKG_MANAGER" in
    brew)    pkg_install "radare2" ;;
    apt)     pkg_install "radare2" ;;
    dnf)     pkg_install "radare2" ;;
    pacman)  pkg_install "radare2" ;;
    *)       manual "Install radare2 from https://github.com/radareorg/radare2" ;;
  esac

  ok "radare2 installed"

  # Try to install r2ghidra plugin for decompilation
  if command -v r2pm &>/dev/null; then
    info "Installing r2ghidra decompiler plugin..."
    r2pm -ci r2ghidra 2>/dev/null || info "r2ghidra install failed — decompilation will use disassembly fallback"
  fi
}

install_rizin() {
  if command -v rizin &>/dev/null; then
    ok "rizin already installed"
    return 0
  fi

  case "$PKG_MANAGER" in
    brew)    pkg_install "rizin" ;;
    apt)     pkg_install "rizin" ;;
    *)       manual "Install rizin from https://github.com/rizinorg/rizin" ;;
  esac

  ok "rizin installed"
}

install_ghidra() {
  if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]] && [[ -f "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" ]]; then
    ok "Ghidra already installed at GHIDRA_INSTALL_DIR"
    return 0
  fi
  if command -v analyzeHeadless &>/dev/null; then
    ok "Ghidra headless already in PATH"
    return 0
  fi

  if [[ "$PKG_MANAGER" == "brew" ]]; then
    info "Installing Ghidra via Homebrew Cask..."
    if brew install --cask ghidra 2>/dev/null; then
      ok "Ghidra installed via Homebrew"
      info "Set GHIDRA_INSTALL_DIR to the Ghidra installation path"
      return 0
    fi
  fi

  manual "Download Ghidra from https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR"
}

case "$DEP" in
  ipsw)                   install_ipsw ;;
  xcode-cli-tools|xcode)  install_xcode_cli_tools ;;
  libplist|plistutil)     install_libplist ;;
  jtool2|jtool)           install_jtool2 ;;
  frida)                  install_frida ;;
  libimobiledevice)       install_libimobiledevice ;;
  swift-demangle)         install_swift_demangle ;;
  radare2|r2)             install_radare2 ;;
  rizin|rz)               install_rizin ;;
  ghidra)                 install_ghidra ;;
  *)
    echo "Error: Unknown dependency '$DEP'" >&2
    echo "Available: ipsw, xcode-cli-tools, libplist, jtool2, frida, libimobiledevice, swift-demangle, radare2, rizin, ghidra" >&2
    exit 1
    ;;
esac
