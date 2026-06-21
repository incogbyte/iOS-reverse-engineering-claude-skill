#!/usr/bin/env bash
# extract-ipa.sh — Extract and analyze iOS IPA, .app, Mach-O, .dylib, .framework files
set -euo pipefail

usage() {
  cat <<EOF
Usage: extract-ipa.sh [OPTIONS] <file>

Extract and analyze an iOS application.

Arguments:
  <file>            Path to .ipa, .app directory, Mach-O binary, .dylib, or .framework

Options:
  -o, --output DIR      Output directory (default: <filename>-analysis)
  --no-classdump        Skip class-dump extraction
  --thin <arch>         Extract specific architecture from fat binaries (e.g., arm64)
  --swift-demangle      Demangle Swift symbols in output
  -h, --help            Show this help message

Examples:
  extract-ipa.sh MyApp.ipa
  extract-ipa.sh --swift-demangle MyApp.ipa
  extract-ipa.sh --thin arm64 MyApp.app
  extract-ipa.sh --no-classdump MyFramework.framework
EOF
  exit 0
}

# --- Parse arguments ---
OUTPUT_DIR=""
NO_CLASSDUMP=false
THIN_ARCH=""
SWIFT_DEMANGLE=false
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)       OUTPUT_DIR="$2"; shift 2 ;;
    --no-classdump)    NO_CLASSDUMP=true; shift ;;
    --thin)            THIN_ARCH="$2"; shift 2 ;;
    --swift-demangle)  SWIFT_DEMANGLE=true; shift ;;
    -h|--help)         usage ;;
    -*)                echo "Error: Unknown option $1" >&2; usage ;;
    *)                 INPUT_FILE="$1"; shift ;;
  esac
done

# --- Validate input ---
if [[ -z "$INPUT_FILE" ]]; then
  echo "Error: No input file specified." >&2
  usage
fi

if [[ ! -e "$INPUT_FILE" ]]; then
  echo "Error: File/directory not found: $INPUT_FILE" >&2
  exit 1
fi

# Determine input type
INPUT_TYPE=""
if [[ -d "$INPUT_FILE" ]]; then
  if [[ "$INPUT_FILE" == *.app ]]; then
    INPUT_TYPE="app"
  elif [[ "$INPUT_FILE" == *.framework ]]; then
    INPUT_TYPE="framework"
  else
    echo "Error: Directory input must be a .app bundle or .framework" >&2
    exit 1
  fi
else
  ext="${INPUT_FILE##*.}"
  ext_lower=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
  case "$ext_lower" in
    ipa)       INPUT_TYPE="ipa" ;;
    dylib)     INPUT_TYPE="dylib" ;;
    framework) INPUT_TYPE="framework" ;;
    *)
      # Check if it's a Mach-O binary by magic bytes
      if file "$INPUT_FILE" | grep -qi "Mach-O\|Mach-O"; then
        INPUT_TYPE="macho"
      else
        echo "Error: Unsupported file type. Expected .ipa, .app, .dylib, .framework, or Mach-O binary" >&2
        exit 1
      fi
      ;;
  esac
fi

BASENAME=$(basename "$INPUT_FILE" | sed 's/\.[^.]*$//')
INPUT_FILE_ABS=$(realpath "$INPUT_FILE")

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="${BASENAME}-analysis"
fi

mkdir -p "$OUTPUT_DIR"
echo "=== iOS Reverse Engineering: Analyzing $INPUT_FILE ==="
echo "Input type: $INPUT_TYPE"
echo "Output directory: $OUTPUT_DIR"
echo

# --- Helper: find the main binary in an .app bundle ---
find_main_binary() {
  local app_dir="$1"
  local binary_name=""

  # Try Info.plist first
  if [[ -f "$app_dir/Info.plist" ]]; then
    if command -v plutil &>/dev/null; then
      binary_name=$(plutil -extract CFBundleExecutable raw "$app_dir/Info.plist" 2>/dev/null || true)
    elif command -v /usr/libexec/PlistBuddy &>/dev/null; then
      binary_name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$app_dir/Info.plist" 2>/dev/null || true)
    elif command -v plistutil &>/dev/null; then
      binary_name=$(plistutil -i "$app_dir/Info.plist" -f xml 2>/dev/null | grep -A1 'CFBundleExecutable' | grep '<string>' | sed 's/.*<string>\(.*\)<\/string>.*/\1/' || true)
    fi
  fi

  if [[ -n "$binary_name" ]] && [[ -f "$app_dir/$binary_name" ]]; then
    echo "$app_dir/$binary_name"
    return
  fi

  # Fallback: find the first Mach-O file in the bundle root
  for f in "$app_dir"/*; do
    if [[ -f "$f" ]] && file "$f" 2>/dev/null | grep -qi "Mach-O"; then
      echo "$f"
      return
    fi
  done

  return 1
}

# --- Helper: extract Info.plist ---
extract_plist() {
  local plist="$1"
  local dest="$2"

  if [[ ! -f "$plist" ]]; then
    echo "  Info.plist not found"
    return
  fi

  cp "$plist" "$dest/Info.plist"

  echo "  Extracting Info.plist metadata..."

  if command -v plutil &>/dev/null; then
    # Convert binary plist to XML for readability
    plutil -convert xml1 -o "$dest/Info.plist" "$plist" 2>/dev/null || cp "$plist" "$dest/Info.plist"

    # Extract key fields
    local bundle_id display_name min_ios ats_settings
    bundle_id=$(plutil -extract CFBundleIdentifier raw "$dest/Info.plist" 2>/dev/null || echo "unknown")
    display_name=$(plutil -extract CFBundleDisplayName raw "$dest/Info.plist" 2>/dev/null || \
                   plutil -extract CFBundleName raw "$dest/Info.plist" 2>/dev/null || echo "unknown")
    min_ios=$(plutil -extract MinimumOSVersion raw "$dest/Info.plist" 2>/dev/null || echo "unknown")

    echo "  Bundle ID: $bundle_id"
    echo "  Display Name: $display_name"
    echo "  Minimum iOS: $min_ios"

    # Check ATS settings
    if plutil -extract NSAppTransportSecurity raw "$dest/Info.plist" &>/dev/null; then
      echo "  [!] App Transport Security configuration found"
      plutil -extract NSAppTransportSecurity xml1 -o "$dest/ats-config.plist" "$dest/Info.plist" 2>/dev/null || true
      if [[ -f "$dest/ats-config.plist" ]]; then
        cat "$dest/ats-config.plist"
      fi
    fi

    # Check URL schemes
    if plutil -extract CFBundleURLTypes raw "$dest/Info.plist" &>/dev/null; then
      echo "  URL schemes found:"
      plutil -extract CFBundleURLTypes xml1 -o - "$dest/Info.plist" 2>/dev/null || true
    fi

    # Check background modes
    if plutil -extract UIBackgroundModes raw "$dest/Info.plist" &>/dev/null; then
      echo "  Background modes:"
      plutil -extract UIBackgroundModes xml1 -o - "$dest/Info.plist" 2>/dev/null || true
    fi
  elif command -v plistutil &>/dev/null; then
    plistutil -i "$plist" -f xml -o "$dest/Info.plist" 2>/dev/null || cp "$plist" "$dest/Info.plist"
    echo "  (Use 'cat $dest/Info.plist' to view full plist)"
  else
    cp "$plist" "$dest/Info.plist"
    echo "  (plutil not available — plist copied as-is)"
  fi
}

# --- Helper: extract entitlements ---
extract_entitlements() {
  local binary="$1"
  local dest="$2"

  if command -v codesign &>/dev/null; then
    echo "  Extracting entitlements..."
    codesign -d --entitlements - "$binary" > "$dest/entitlements.plist" 2>/dev/null || true
    if [[ -s "$dest/entitlements.plist" ]]; then
      echo "  Entitlements extracted"
      # Show key entitlements
      if command -v plutil &>/dev/null; then
        grep -E "keychain-access-groups|application-identifier|aps-environment|associated-domains|com.apple.developer" "$dest/entitlements.plist" 2>/dev/null | head -20 || true
      fi
    else
      echo "  No entitlements found (unsigned or stripped)"
      rm -f "$dest/entitlements.plist"
    fi
  elif command -v jtool2 &>/dev/null; then
    echo "  Extracting entitlements with jtool2..."
    jtool2 --ent "$binary" > "$dest/entitlements.plist" 2>/dev/null || true
  elif command -v ipsw &>/dev/null; then
    # Cross-platform fallback (Linux): ipsw macho info -e prints entitlements
    echo "  Extracting entitlements with ipsw..."
    local ent
    ent=$(ipsw_macho_info "-e" "$binary")
    if [[ -n "$ent" ]] && ! grep -qi 'no entitlement' <<<"$ent"; then
      printf '%s\n' "$ent" > "$dest/entitlements.plist"
      echo "  Entitlements extracted"
    else
      echo "  No entitlements found (unsigned or stripped)"
      rm -f "$dest/entitlements.plist"
    fi
  else
    echo "  (codesign/jtool2/ipsw not available — skipping entitlements)"
  fi
}

# --- Helper: run ipsw class-dump ---
run_classdump() {
  local binary="$1"
  local dest="$2"

  if [[ "$NO_CLASSDUMP" == true ]]; then
    echo "  Skipping class-dump (--no-classdump)"
    return
  fi

  local ipsw_cmd=""
  if command -v ipsw &>/dev/null; then
    ipsw_cmd="ipsw"
  elif [[ -x "$HOME/.local/bin/ipsw" ]]; then
    ipsw_cmd="$HOME/.local/bin/ipsw"
  elif [[ -x "/opt/homebrew/bin/ipsw" ]]; then
    ipsw_cmd="/opt/homebrew/bin/ipsw"
  fi

  if [[ -z "$ipsw_cmd" ]]; then
    echo "  [WARN] ipsw not found — skipping header extraction"
    echo "  Install with: brew install blacktop/tap/ipsw"
    return
  fi

  mkdir -p "$dest/class-dump"

  echo "  Running ipsw class-dump on $(basename "$binary")..."

  local cd_args=()
  if [[ -n "$THIN_ARCH" ]]; then
    cd_args+=("--arch" "$THIN_ARCH")
  fi

  # Run ipsw class-dump, output headers to directory
  if $ipsw_cmd class-dump ${cd_args[@]+"${cd_args[@]}"} -H -o "$dest/class-dump" "$binary" 2>"$dest/class-dump/errors.log"; then
    local count
    count=$(find "$dest/class-dump" -name "*.h" 2>/dev/null | wc -l | tr -d ' ')
    echo "  Headers extracted: $count"

    if [[ -s "$dest/class-dump/errors.log" ]]; then
      local error_count
      error_count=$(wc -l < "$dest/class-dump/errors.log" | tr -d ' ')
      echo "  Warnings/errors: $error_count (see class-dump/errors.log)"
    else
      rm -f "$dest/class-dump/errors.log"
    fi
  else
    echo "  [WARN] ipsw class-dump failed (binary may be encrypted or unsupported)"
    echo "  See $dest/class-dump/errors.log for details"
    # Try alternative: dump all to single file (ObjC only)
    $ipsw_cmd class-dump ${cd_args[@]+"${cd_args[@]}"} "$binary" > "$dest/class-dump/all-headers.h" 2>/dev/null || true
    if [[ -s "$dest/class-dump/all-headers.h" ]]; then
      echo "  Partial output saved to class-dump/all-headers.h"
    fi
  fi

  # Optionally demangle Swift symbols
  if [[ "$SWIFT_DEMANGLE" == true ]]; then
    echo "  Demangling Swift symbols..."
    if command -v swift-demangle &>/dev/null; then
      find "$dest/class-dump" -name "*.h" -exec sh -c '
        swift-demangle < "$1" > "$1.demangled" && mv "$1.demangled" "$1"
      ' _ {} \;
    elif command -v swift &>/dev/null; then
      find "$dest/class-dump" -name "*.h" -exec sh -c '
        swift demangle < "$1" > "$1.demangled" 2>/dev/null && mv "$1.demangled" "$1"
      ' _ {} \;
    fi
    echo "  Swift symbols demangled"
  fi
}

# --- Helper: extract strings ---
extract_strings() {
  local binary="$1"
  local dest="$2"

  echo "  Extracting strings from binary..."
  if command -v strings &>/dev/null; then
    strings "$binary" > "$dest/strings-raw.txt" 2>/dev/null

    # Filter for interesting strings
    grep -iE 'https?://|api[_.-]|/v[0-9]+/|\.com/|\.io/|\.net/|token|key|secret|password|auth|bearer|login|register|endpoint' \
      "$dest/strings-raw.txt" > "$dest/strings-urls-and-keys.txt" 2>/dev/null || true

    grep -iE '\.plist|\.json|\.xml|\.sqlite|\.db|\.realm|keychain|UserDefaults|NSCoding' \
      "$dest/strings-raw.txt" > "$dest/strings-storage.txt" 2>/dev/null || true

    local total_count url_count
    total_count=$(wc -l < "$dest/strings-raw.txt" | tr -d ' ')
    url_count=$(wc -l < "$dest/strings-urls-and-keys.txt" | tr -d ' ')
    echo "  Total strings: $total_count"
    echo "  URLs/keys/auth strings: $url_count"
  else
    echo "  [WARN] strings command not found"
  fi
}

# --- Helper: pick a --arch arg for ipsw on a (possibly fat) Mach-O ---
# Echoes "--arch <arch>" if the binary is fat/universal and an arch can be determined,
# otherwise echoes "" (single-arch binaries don't trigger ipsw's interactive arch selector).
# Passing --arch explicitly is what lets `ipsw macho info` run non-interactively on fat binaries.
_ipsw_arch_arg() {
  local binary="$1"
  if ! file "$binary" 2>/dev/null | grep -qi 'universal\|fat'; then
    echo ""
    return
  fi
  local arch="$THIN_ARCH"
  if [[ -z "$arch" ]]; then
    # First arch from `file` output, e.g. "[x86_64:Mach-O ...] [arm64:...]" -> x86_64
    arch=$(file "$binary" 2>/dev/null | grep -oE '\[[a-z0-9_]+:' | head -1 | tr -d '[]:')
  fi
  if [[ -n "$arch" ]]; then
    echo "--arch $arch"
  else
    echo "--arch arm64"   # iOS default fallback
  fi
}

# --- Helper: run `ipsw macho info` non-interactively (arch-aware, no color) ---
# $1 = info flag(s) e.g. "-d", "-l", "-e", "-o", "-n";  $2 = binary
ipsw_macho_info() {
  local flags="$1" binary="$2"
  local archarg
  archarg=$(_ipsw_arch_arg "$binary")
  # shellcheck disable=SC2086
  ipsw macho info --no-color $archarg $flags "$binary" 2>/dev/null || true
}

# --- Helper: analyze Mach-O binary ---
analyze_macho() {
  local binary="$1"
  local dest="$2"

  echo "  Analyzing Mach-O binary..."

  # File type info
  file "$binary" > "$dest/binary-info.txt" 2>/dev/null

  # Architecture info
  if command -v lipo &>/dev/null; then
    echo "  Architectures:"
    lipo -info "$binary" 2>/dev/null | tee -a "$dest/binary-info.txt" || true
  elif command -v ipsw &>/dev/null; then
    # Linux: no lipo; record arch from ipsw header
    ipsw_macho_info "-d" "$binary" | grep -iE '^(Magic|Type|CPU)' >> "$dest/binary-info.txt" || true
  fi

  # Handle fat binary thinning (macOS lipo; cross-platform ipsw macho lipo)
  if [[ -n "$THIN_ARCH" ]]; then
    if command -v lipo &>/dev/null; then
      local thin_binary="$dest/$(basename "$binary")-${THIN_ARCH}"
      if lipo -thin "$THIN_ARCH" "$binary" -output "$thin_binary" 2>/dev/null; then
        echo "  Thinned to $THIN_ARCH: $thin_binary"
        binary="$thin_binary"
      else
        echo "  [WARN] Could not thin to $THIN_ARCH — using fat binary (ipsw will use --arch)"
      fi
    else
      echo "  [NOTE] lipo unavailable — keeping fat binary; ipsw uses --arch $THIN_ARCH"
    fi
  fi

  # Shared libraries / linked frameworks / load commands / ObjC / header flags
  if command -v otool &>/dev/null; then
    echo "  Linked libraries:"
    otool -L "$binary" 2>/dev/null | tee "$dest/linked-libraries.txt"

    # Load commands summary
    otool -l "$binary" 2>/dev/null > "$dest/load-commands.txt"
    echo "  Load commands saved to load-commands.txt"

    # Objective-C info
    otool -oV "$binary" 2>/dev/null > "$dest/objc-info.txt" || true
    if [[ -s "$dest/objc-info.txt" ]]; then
      echo "  Objective-C metadata saved to objc-info.txt"
    else
      rm -f "$dest/objc-info.txt"
    fi

    # Mach-O header flags (PIE etc.) — for the hardening audit
    otool -hv "$binary" 2>/dev/null > "$dest/macho-flags.txt" || true
  elif command -v ipsw &>/dev/null; then
    # Linux / no-otool fallback: ipsw macho info provides all of the above
    echo "  Linked libraries (via ipsw):"
    ipsw_macho_info "-l" "$binary" | grep -E 'LC_LOAD_DYLIB' | tee "$dest/linked-libraries.txt" || true

    ipsw_macho_info "-l" "$binary" > "$dest/load-commands.txt" || true
    [[ -s "$dest/load-commands.txt" ]] && echo "  Load commands saved to load-commands.txt" || rm -f "$dest/load-commands.txt"

    ipsw_macho_info "-o" "$binary" > "$dest/objc-info.txt" || true
    if [[ -s "$dest/objc-info.txt" ]] && ! grep -qi 'no objc' "$dest/objc-info.txt"; then
      echo "  Objective-C metadata saved to objc-info.txt"
    else
      rm -f "$dest/objc-info.txt"
    fi

    # Mach-O header flags (PIE etc.) via ipsw macho info -d (header)
    ipsw_macho_info "-d" "$binary" > "$dest/macho-flags.txt" || true
    [[ -s "$dest/macho-flags.txt" ]] || rm -f "$dest/macho-flags.txt"
  else
    echo "  [WARN] Neither otool nor ipsw available — skipping Mach-O analysis"
  fi

  # Symbol table (nm is cross-platform via binutils; ipsw -n as fallback)
  if command -v nm &>/dev/null; then
    nm "$binary" 2>/dev/null > "$dest/symbols.txt" || true
  elif command -v ipsw &>/dev/null; then
    ipsw_macho_info "-n" "$binary" > "$dest/symbols.txt" || true
  fi
  if [[ -s "$dest/symbols.txt" ]]; then
    local sym_count
    sym_count=$(wc -l < "$dest/symbols.txt" | tr -d ' ')
    echo "  Symbols: $sym_count"

    if [[ "$SWIFT_DEMANGLE" == true ]]; then
      if command -v swift-demangle &>/dev/null; then
        swift-demangle < "$dest/symbols.txt" > "$dest/symbols-demangled.txt" 2>/dev/null
      elif command -v swift &>/dev/null; then
        swift demangle < "$dest/symbols.txt" > "$dest/symbols-demangled.txt" 2>/dev/null
      fi
    fi
  else
    echo "  No symbols (stripped binary or no nm/ipsw)"
    rm -f "$dest/symbols.txt"
  fi
}

# --- Helper: list embedded frameworks ---
list_frameworks() {
  local app_dir="$1"
  local dest="$2"

  local fw_dir="$app_dir/Frameworks"
  if [[ -d "$fw_dir" ]]; then
    echo "  Embedded frameworks:"
    mkdir -p "$dest/frameworks"
    for fw in "$fw_dir"/*; do
      local fw_name
      fw_name=$(basename "$fw")
      echo "    - $fw_name"
      echo "$fw_name" >> "$dest/frameworks/list.txt"
    done
  else
    echo "  No embedded frameworks found"
  fi

  # Check for PlugIns (extensions)
  local plugins_dir="$app_dir/PlugIns"
  if [[ -d "$plugins_dir" ]]; then
    echo "  App Extensions:"
    for ext_bundle in "$plugins_dir"/*; do
      echo "    - $(basename "$ext_bundle")"
    done
  fi
}

# --- Helper: copy Apple privacy manifest (PrivacyInfo.xcprivacy) ---
# The manifest is a plist with a non-.plist suffix, so the generic *.plist copy loop misses it.
# It is required by Apple for apps/SDKs using required-reason APIs; surfaced for the privacy audit.
copy_privacy_manifest() {
  local app_dir="$1"
  local dest="$2"
  local manifest="$app_dir/PrivacyInfo.xcprivacy"
  if [[ -f "$manifest" ]]; then
    cp "$manifest" "$dest/PrivacyInfo.xcprivacy" 2>/dev/null || true
    echo "  PrivacyInfo.xcprivacy copied"
  fi
}

# =====================================================================
# Main extraction logic
# =====================================================================

APP_DIR=""
MAIN_BINARY=""

case "$INPUT_TYPE" in
  ipa)
    echo "=== Extracting IPA ==="
    IPA_EXTRACT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ipa-extract-XXXXXX")
    unzip -qo "$INPUT_FILE_ABS" -d "$IPA_EXTRACT_DIR"

    # Find the .app bundle inside Payload/
    APP_DIR=$(find "$IPA_EXTRACT_DIR/Payload" -maxdepth 1 -name "*.app" -type d | head -1)
    if [[ -z "$APP_DIR" ]]; then
      echo "Error: No .app bundle found inside IPA" >&2
      rm -rf "$IPA_EXTRACT_DIR"
      exit 1
    fi

    echo "  Found app bundle: $(basename "$APP_DIR")"
    echo

    # Find main binary
    MAIN_BINARY=$(find_main_binary "$APP_DIR")
    if [[ -z "$MAIN_BINARY" ]]; then
      echo "Error: Could not find main binary in app bundle" >&2
      rm -rf "$IPA_EXTRACT_DIR"
      exit 1
    fi
    echo "  Main binary: $(basename "$MAIN_BINARY")"
    echo

    # Extract metadata
    echo "--- Metadata ---"
    extract_plist "$APP_DIR/Info.plist" "$OUTPUT_DIR"
    extract_entitlements "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    # Analyze binary
    echo "--- Binary Analysis ---"
    analyze_macho "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    # Class dump
    echo "--- Class Dump ---"
    run_classdump "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    # Strings
    echo "--- String Extraction ---"
    extract_strings "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    # Frameworks
    echo "--- Frameworks ---"
    list_frameworks "$APP_DIR" "$OUTPUT_DIR"
    echo

    # Copy useful resources
    if [[ -d "$APP_DIR/Base.lproj" ]]; then
      cp -r "$APP_DIR/Base.lproj" "$OUTPUT_DIR/Base.lproj" 2>/dev/null || true
    fi

    # Copy storyboard files list
    find "$APP_DIR" -name "*.storyboardc" -o -name "*.nib" 2>/dev/null | \
      sed "s|$APP_DIR/||" > "$OUTPUT_DIR/ui-files.txt" 2>/dev/null || true

    # Copy any embedded plists
    mkdir -p "$OUTPUT_DIR/plists"
    find "$APP_DIR" -name "*.plist" -not -path "*/Frameworks/*" -not -path "*/PlugIns/*" 2>/dev/null | while read -r plist; do
      rel_name=$(echo "$plist" | sed "s|$APP_DIR/||" | tr '/' '_')
      cp "$plist" "$OUTPUT_DIR/plists/$rel_name" 2>/dev/null || true
    done

    # Apple privacy manifest (required-reason APIs)
    copy_privacy_manifest "$APP_DIR" "$OUTPUT_DIR"

    # Cleanup
    rm -rf "$IPA_EXTRACT_DIR"
    ;;

  app)
    APP_DIR="$INPUT_FILE_ABS"
    MAIN_BINARY=$(find_main_binary "$APP_DIR")
    if [[ -z "$MAIN_BINARY" ]]; then
      echo "Error: Could not find main binary in app bundle" >&2
      exit 1
    fi
    echo "  Main binary: $(basename "$MAIN_BINARY")"
    echo

    echo "--- Metadata ---"
    extract_plist "$APP_DIR/Info.plist" "$OUTPUT_DIR"
    extract_entitlements "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- Binary Analysis ---"
    analyze_macho "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- Class Dump ---"
    run_classdump "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- String Extraction ---"
    extract_strings "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- Frameworks ---"
    list_frameworks "$APP_DIR" "$OUTPUT_DIR"
    echo

    # Apple privacy manifest (required-reason APIs)
    copy_privacy_manifest "$APP_DIR" "$OUTPUT_DIR"
    ;;

  framework)
    # Find the binary inside the framework
    FW_NAME=$(basename "$INPUT_FILE_ABS" .framework)
    if [[ -d "$INPUT_FILE_ABS" ]]; then
      MAIN_BINARY="$INPUT_FILE_ABS/$FW_NAME"
    else
      MAIN_BINARY="$INPUT_FILE_ABS"
    fi

    if [[ ! -f "$MAIN_BINARY" ]]; then
      echo "Error: Binary not found at $MAIN_BINARY" >&2
      exit 1
    fi

    echo "--- Binary Analysis ---"
    analyze_macho "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- Class Dump ---"
    run_classdump "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- String Extraction ---"
    extract_strings "$MAIN_BINARY" "$OUTPUT_DIR"

    # Extract Info.plist if present
    if [[ -d "$INPUT_FILE_ABS" ]] && [[ -f "$INPUT_FILE_ABS/Info.plist" ]]; then
      echo
      echo "--- Metadata ---"
      extract_plist "$INPUT_FILE_ABS/Info.plist" "$OUTPUT_DIR"
    fi
    ;;

  dylib|macho)
    MAIN_BINARY="$INPUT_FILE_ABS"

    echo "--- Binary Analysis ---"
    analyze_macho "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- Class Dump ---"
    run_classdump "$MAIN_BINARY" "$OUTPUT_DIR"
    echo

    echo "--- String Extraction ---"
    extract_strings "$MAIN_BINARY" "$OUTPUT_DIR"
    ;;
esac

echo
echo "=== Analysis complete ==="
echo "Output directory: $OUTPUT_DIR"
echo
echo "Contents:"
ls -1 "$OUTPUT_DIR/" 2>/dev/null || true
if [[ -d "$OUTPUT_DIR/class-dump" ]]; then
  header_count=$(find "$OUTPUT_DIR/class-dump" -name "*.h" 2>/dev/null | wc -l | tr -d ' ')
  echo "  class-dump/ ($header_count headers)"
fi
