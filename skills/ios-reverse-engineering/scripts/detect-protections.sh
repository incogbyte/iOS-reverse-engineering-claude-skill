#!/usr/bin/env bash
# detect-protections.sh — Detect anti-tampering, obfuscation, and protection mechanisms in iOS apps
set -euo pipefail

usage() {
  cat <<EOF
Usage: detect-protections.sh <analysis-dir> [OPTIONS]

Detect anti-tampering, obfuscation, and security protection mechanisms
in an iOS application. Searches binary analysis output, class-dump headers,
strings, symbols, and load commands.

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --binary FILE     Path to the Mach-O binary (for direct binary analysis)
  --obfuscation     Check only for obfuscation indicators
  --integrity       Check only for integrity/tampering checks
  --debugger        Check only for anti-debugging protections
  --injection       Check only for dylib injection prevention
  --jailbreak       Check only for jailbreak detection
  --encryption      Check only for binary encryption (FairPlay DRM)
  --all             Check all protection types (default)
  --report FILE     Export results as Markdown report to FILE
  -h, --help        Show this help message

Output:
  Detected protections with type, confidence level, and evidence.
EOF
  exit 0
}

ANALYSIS_DIR=""
BINARY_FILE=""
DO_OBFUSCATION=false
DO_INTEGRITY=false
DO_DEBUGGER=false
DO_INJECTION=false
DO_JAILBREAK=false
DO_ENCRYPTION=false
DO_ALL=true
REPORT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)      BINARY_FILE="$2"; shift 2 ;;
    --obfuscation) DO_OBFUSCATION=true; DO_ALL=false; shift ;;
    --integrity)   DO_INTEGRITY=true;   DO_ALL=false; shift ;;
    --debugger)    DO_DEBUGGER=true;    DO_ALL=false; shift ;;
    --injection)   DO_INJECTION=true;   DO_ALL=false; shift ;;
    --jailbreak)   DO_JAILBREAK=true;   DO_ALL=false; shift ;;
    --encryption)  DO_ENCRYPTION=true;  DO_ALL=false; shift ;;
    --all)         DO_ALL=true; shift ;;
    --report)      REPORT_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    -*)            echo "Error: Unknown option $1" >&2; usage ;;
    *)             ANALYSIS_DIR="$1"; shift ;;
  esac
done

if [[ -z "$ANALYSIS_DIR" ]]; then
  echo "Error: No analysis directory specified." >&2
  usage
fi

if [[ ! -d "$ANALYSIS_DIR" ]]; then
  echo "Error: Directory not found: $ANALYSIS_DIR" >&2
  exit 1
fi

# =====================================================================
# Helpers
# =====================================================================

FINDINGS=()
FINDING_TYPES=()
FINDING_SEVERITIES=()
FINDING_CONFIDENCES=()
FINDING_EVIDENCES=()

add_finding() {
  local type="$1"
  local severity="$2"
  local confidence="$3"
  local description="$4"
  local evidence="$5"

  FINDINGS+=("$description")
  FINDING_TYPES+=("$type")
  FINDING_SEVERITIES+=("$severity")
  FINDING_CONFIDENCES+=("$confidence")
  FINDING_EVIDENCES+=("$evidence")

  printf "  [%s][%s] %s\n" "$severity" "$confidence" "$description"
}

# Search across all analysis files
search_files() {
  local pattern="$1"
  local case_flag="${2:--i}"
  local results=""

  # Class-dump headers
  if [[ -d "$ANALYSIS_DIR/class-dump" ]]; then
    results+=$(grep -rl $case_flag "$pattern" "$ANALYSIS_DIR/class-dump/" 2>/dev/null | head -5 || true)
    results+=$(grep -rn $case_flag "$pattern" "$ANALYSIS_DIR/class-dump/" 2>/dev/null | head -10 || true)
  fi

  # Strings
  if [[ -f "$ANALYSIS_DIR/strings-raw.txt" ]]; then
    results+=$(grep $case_flag "$pattern" "$ANALYSIS_DIR/strings-raw.txt" 2>/dev/null | head -10 || true)
  fi

  # Symbols
  if [[ -f "$ANALYSIS_DIR/symbols.txt" ]]; then
    results+=$(grep $case_flag "$pattern" "$ANALYSIS_DIR/symbols.txt" 2>/dev/null | head -10 || true)
  fi
  if [[ -f "$ANALYSIS_DIR/symbols-demangled.txt" ]]; then
    results+=$(grep $case_flag "$pattern" "$ANALYSIS_DIR/symbols-demangled.txt" 2>/dev/null | head -5 || true)
  fi

  echo "$results"
}

search_binary_strings() {
  local pattern="$1"
  if [[ -f "$ANALYSIS_DIR/strings-raw.txt" ]]; then
    grep -i "$pattern" "$ANALYSIS_DIR/strings-raw.txt" 2>/dev/null | head -10 || true
  fi
}

search_load_commands() {
  local pattern="$1"
  if [[ -f "$ANALYSIS_DIR/load-commands.txt" ]]; then
    grep -i "$pattern" "$ANALYSIS_DIR/load-commands.txt" 2>/dev/null || true
  fi
}

search_linked_libs() {
  local pattern="$1"
  if [[ -f "$ANALYSIS_DIR/linked-libraries.txt" ]]; then
    grep -i "$pattern" "$ANALYSIS_DIR/linked-libraries.txt" 2>/dev/null || true
  fi
}

# macho_load_commands <binary> -> echo raw Mach-O load commands for direct-binary analysis.
# macOS: otool -l. Linux/cross fallback: ipsw macho info -l (on a single-arch binary).
# ipsw launches an interactive TUI on fat binaries, so we thin to the first arch first.
_macho_info_arch_arg() {
  local binary="$1"
  if ! file "$binary" 2>/dev/null | grep -qi 'universal\|fat'; then echo ""; return; fi
  local arch
  arch=$(file "$binary" 2>/dev/null | grep -oE '\[[a-z0-9_]+:' | head -1 | tr -d '[]:')
  if [[ -n "$arch" ]]; then echo "--arch $arch"; else echo "--arch arm64"; fi
}

macho_load_commands() {
  local binary="$1"
  [[ -n "$binary" && -f "$binary" ]] || return 0
  if command -v otool &>/dev/null; then
    otool -l "$binary" 2>/dev/null || true
    return
  fi
  if command -v ipsw &>/dev/null; then
    local archarg; archarg=$(_macho_info_arch_arg "$binary")
    ipsw macho info --no-color $archarg -l "$binary" 2>/dev/null || true
    return
  fi
  return 0
}

echo "=== iOS Protection & Anti-Tampering Detection ==="
echo "Analysis directory: $ANALYSIS_DIR"
echo

# =====================================================================
# 1. Obfuscation Detection
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_OBFUSCATION" == true ]]; then
  echo "--- Obfuscation Analysis ---"

  # Check for known obfuscation tools
  # iXGuard / DexGuard iOS
  result=$(search_files "iXGuard\|ixguard\|GuardSquare")
  if [[ -n "$result" ]]; then
    add_finding "Obfuscation" "INFO" "HIGH" "iXGuard (GuardSquare) obfuscation detected" "GuardSquare/iXGuard references found"
  fi

  # SwiftShield
  result=$(search_files "SwiftShield\|swiftshield")
  if [[ -n "$result" ]]; then
    add_finding "Obfuscation" "INFO" "HIGH" "SwiftShield obfuscation detected" "SwiftShield references found"
  fi

  # Obfuscator-LLVM (O-LLVM)
  result=$(search_files "ollvm\|obfuscator-llvm\|bcf\|fla\|sub")
  if [[ -n "$result" ]]; then
    # Check for specific O-LLVM patterns in symbols
    result2=$(search_files "\._Z.*_Z.*_Z" "-")
    if [[ -n "$result2" ]]; then
      add_finding "Obfuscation" "INFO" "MEDIUM" "Possible OLLVM (Obfuscator-LLVM) patterns detected" "Mangled symbols suggest control flow flattening"
    fi
  fi

  # Arxan / Digital.ai
  result=$(search_files "arxan\|Arxan\|TransformIT\|digital\.ai")
  if [[ -n "$result" ]]; then
    add_finding "Obfuscation" "INFO" "HIGH" "Arxan (Digital.ai) protection detected" "Arxan/TransformIT references found"
  fi

  # Dexprotector iOS
  result=$(search_files "liprotector\|dexprotect\|Licel")
  if [[ -n "$result" ]]; then
    add_finding "Obfuscation" "INFO" "HIGH" "DexProtector/Licel protection detected" "Protection framework references found"
  fi

  # Check for heavily obfuscated class/method names
  if [[ -d "$ANALYSIS_DIR/class-dump" ]]; then
    # Count classes with short random-looking names (like 'a', 'b', 'Ax3f', etc.)
    obfuscated_count=$(find "$ANALYSIS_DIR/class-dump" -name "*.h" -exec basename {} .h \; 2>/dev/null | \
      grep -cE '^[a-zA-Z]{1,3}$|^[a-zA-Z][0-9]+$|^_[A-Z]{2,6}$' 2>/dev/null || echo "0")
    total_headers=$(find "$ANALYSIS_DIR/class-dump" -name "*.h" 2>/dev/null | wc -l | tr -d ' ')

    if [[ "$total_headers" -gt 0 ]] && [[ "$obfuscated_count" -gt 20 ]]; then
      ratio=$((obfuscated_count * 100 / total_headers))
      if [[ "$ratio" -gt 30 ]]; then
        add_finding "Obfuscation" "INFO" "HIGH" "Heavy class name obfuscation detected ($obfuscated_count/$total_headers classes, ${ratio}%)" "Many short/random class names suggest obfuscation tool"
      elif [[ "$ratio" -gt 10 ]]; then
        add_finding "Obfuscation" "INFO" "MEDIUM" "Moderate class name obfuscation detected ($obfuscated_count/$total_headers classes, ${ratio}%)" "Some short/random class names"
      fi
    fi

    # Check for method name obfuscation (single-char method names)
    obf_methods=$(grep -rh "^[-+]" "$ANALYSIS_DIR/class-dump/" 2>/dev/null | \
      grep -cE '[-+]\s*\([^)]+\)\s*[a-z]{1,2};' 2>/dev/null || echo "0")
    if [[ "$obf_methods" -gt 50 ]]; then
      add_finding "Obfuscation" "INFO" "MEDIUM" "Method name obfuscation detected ($obf_methods short method names)" "Single/double character method names"
    fi
  fi

  # Check for encrypted/encoded strings (common in obfuscated apps)
  if [[ -f "$ANALYSIS_DIR/strings-raw.txt" ]]; then
    # Look for base64-heavy strings that might be encrypted constants
    b64_count=$(grep -cE '^[A-Za-z0-9+/]{40,}=*$' "$ANALYSIS_DIR/strings-raw.txt" 2>/dev/null || echo "0")
    if [[ "$b64_count" -gt 20 ]]; then
      add_finding "Obfuscation" "INFO" "MEDIUM" "Possible string encryption detected ($b64_count long base64-like strings)" "May indicate runtime string decryption"
    fi
  fi

  # Check for string decryption routines in symbols
  result=$(search_files "decrypt.*string\|decryptString\|unscramble\|deobfuscate\|xor.*key\|decode.*const")
  if [[ -n "$result" ]]; then
    add_finding "Obfuscation" "INFO" "HIGH" "String decryption/deobfuscation routines detected" "Functions suggest runtime string decryption"
  fi

  echo
fi

# =====================================================================
# 2. Integrity / Tampering Checks
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_INTEGRITY" == true ]]; then
  echo "--- Integrity & Tampering Detection ---"

  # Code signing verification at runtime
  result=$(search_files "SecCodeCheckValidity\|SecStaticCodeCheckValidity\|SecCodeCopySigningInformation\|kSecCSCheckAllArchitectures")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "HIGH" "Runtime code signing verification detected" "SecCode* API usage for integrity checking"
  fi

  # Hash verification of binary
  result=$(search_files "hashOfBinary\|binaryHash\|codeHash\|checksumVerif\|verifyIntegrity\|integrityCheck\|selfCheck\|tamperCheck")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "HIGH" "Binary integrity/hash verification detected" "Self-checking routines found"
  fi

  # Mach-O header validation
  result=$(search_files "mach_header\|MH_MAGIC\|MH_MAGIC_64\|_mh_execute_header\|LC_CODE_SIGNATURE")
  if [[ -n "$result" ]]; then
    result2=$(search_files "validateHeader\|checkHeader\|verifyMachO\|headerIntegrity")
    if [[ -n "$result2" ]]; then
      add_finding "Integrity" "INFO" "HIGH" "Mach-O header integrity validation detected" "Header validation routines"
    fi
  fi

  # Check for file system integrity checks
  result=$(search_files "bundlePath.*hash\|resourceHash\|verifyResources\|checkBundleIntegrity\|fileHash\|hashForPath")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "MEDIUM" "Resource/bundle integrity checking detected" "File hash verification routines"
  fi

  # Check for provisioning profile validation
  result=$(search_files "embedded\.mobileprovision\|verifyProvisioning\|checkProvisioning\|provisioningProfile.*valid")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "MEDIUM" "Provisioning profile validation detected" "Checks for valid provisioning at runtime"
  fi

  # Check for re-signing detection
  result=$(search_files "teamIdentifier\|signingIdentity\|checkSigningTeam\|expectedTeamID\|verifyTeamID")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "HIGH" "Signing team identity verification detected" "Checks the signing team hasn't changed"
  fi

  # App Store receipt validation
  result=$(search_files "appStoreReceiptURL\|SKReceiptRefreshRequest\|validateReceipt\|verifyReceipt\|receiptValidat")
  if [[ -n "$result" ]]; then
    add_finding "Integrity" "INFO" "MEDIUM" "App Store receipt validation detected" "Receipt verification to prevent piracy"
  fi

  echo
fi

# =====================================================================
# 3. Anti-Debugging
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_DEBUGGER" == true ]]; then
  echo "--- Anti-Debugging Detection ---"

  # ptrace(PT_DENY_ATTACH)
  result=$(search_files "ptrace\|PT_DENY_ATTACH\|pt_deny_attach")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "MEDIUM" "HIGH" "ptrace(PT_DENY_ATTACH) anti-debugging detected" "Prevents debugger attachment via ptrace syscall"
  fi

  # sysctl-based debugger detection
  result=$(search_files "sysctl\|CTL_KERN\|KERN_PROC\|P_TRACED\|kinfo_proc")
  if [[ -n "$result" ]]; then
    # Check if actually used for debug detection
    result2=$(search_files "isDebugged\|debuggerAttached\|isBeingDebugged\|detectDebugger\|P_TRACED")
    if [[ -n "$result2" ]]; then
      add_finding "Anti-Debug" "MEDIUM" "HIGH" "sysctl-based debugger detection detected" "Uses sysctl(KERN_PROC) to check P_TRACED flag"
    else
      add_finding "Anti-Debug" "MEDIUM" "LOW" "sysctl usage found (possible debugger detection)" "sysctl present but may be used for other purposes"
    fi
  fi

  # getppid() check (debugger changes parent PID)
  result=$(search_files "getppid\|parentProcess\|checkParentPid")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "LOW" "MEDIUM" "getppid() check detected (possible debugger detection)" "Parent PID check can detect debugger attachment"
  fi

  # Timing-based anti-debug (mach_absolute_time, clock_gettime)
  result=$(search_files "mach_absolute_time\|clock_gettime\|gettimeofday.*debug\|timingCheck\|antiDebugTiming")
  if [[ -n "$result" ]]; then
    result2=$(search_files "timingCheck\|debugTiming\|executionTime.*threshold")
    if [[ -n "$result2" ]]; then
      add_finding "Anti-Debug" "LOW" "MEDIUM" "Timing-based anti-debugging detected" "Measures execution time to detect breakpoints/single-stepping"
    fi
  fi

  # Exception-based anti-debug
  result=$(search_files "task_set_exception_ports\|EXC_BREAKPOINT\|EXC_BAD_ACCESS.*debug\|exception_handler.*debug")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "MEDIUM" "MEDIUM" "Exception-based anti-debugging detected" "Uses Mach exception ports to detect/prevent debugging"
  fi

  # Signal handler anti-debug (SIGTRAP)
  result=$(search_files "SIGTRAP\|signal.*SIG.*debug\|sigaction.*TRAP")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "LOW" "MEDIUM" "SIGTRAP-based anti-debugging detected" "Signal handler may catch debugger-set breakpoints"
  fi

  # isatty / stderr check (debugger redirects)
  result=$(search_files "isatty\|STDERR_FILENO.*debug\|isOutputRedirected")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "LOW" "LOW" "isatty check detected (possible anti-debug)" "Checks if stderr is a terminal (debuggers may redirect)"
  fi

  # Debugserver detection
  result=$(search_files "debugserver\|debug-server\|lldb\|gdb")
  if [[ -n "$result" ]]; then
    result2=$(search_files "detectDebugServer\|findDebugServer\|processName.*debug")
    if [[ -n "$result2" ]]; then
      add_finding "Anti-Debug" "MEDIUM" "HIGH" "Debug server detection routines found" "Scans for debugserver/lldb/gdb processes"
    fi
  fi

  # Disable GDB with assembly
  result=$(search_binary_strings "mov.*x16.*#26\|svc.*#0x80\|syscall.*ptrace")
  if [[ -n "$result" ]]; then
    add_finding "Anti-Debug" "MEDIUM" "MEDIUM" "Inline assembly anti-debug (syscall-based)" "Direct syscall to avoid library-level hooks"
  fi

  echo
fi

# =====================================================================
# 4. Dylib Injection Prevention
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_INJECTION" == true ]]; then
  echo "--- Dylib Injection Prevention ---"

  # Check for __RESTRICT,__restrict section
  if [[ -f "$ANALYSIS_DIR/load-commands.txt" ]]; then
    result=$(search_load_commands "__RESTRICT\|__restrict")
    if [[ -n "$result" ]]; then
      add_finding "Injection" "INFO" "HIGH" "__RESTRICT segment detected in binary" "Prevents DYLD_INSERT_LIBRARIES injection"
    fi
  fi

  # Also check via otool/ipsw on the binary directly (otool macOS, ipsw cross-platform fallback)
  if [[ -n "$BINARY_FILE" ]] && [[ -f "$BINARY_FILE" ]]; then
    restrict=$(macho_load_commands "$BINARY_FILE" | grep -A2 "__RESTRICT" || true)
    if [[ -n "$restrict" ]]; then
      add_finding "Injection" "INFO" "HIGH" "__RESTRICT segment confirmed in Mach-O binary" "Binary has __RESTRICT,__restrict section"
    fi
  fi

  # DYLD_INSERT_LIBRARIES detection
  result=$(search_files "DYLD_INSERT_LIBRARIES\|dyld_insert\|dyld.*insert")
  if [[ -n "$result" ]]; then
    add_finding "Injection" "MEDIUM" "HIGH" "DYLD_INSERT_LIBRARIES environment variable check detected" "App checks for injected libraries"
  fi

  # Check for loaded dylib enumeration
  result=$(search_files "_dyld_image_count\|_dyld_get_image_name\|dyld_image_header\|dladdr\|_dyld_register_func_for_add_image")
  if [[ -n "$result" ]]; then
    # Check if it's being used for validation
    result2=$(search_files "validLib\|whitelistLib\|allowedLib\|expectedLib\|checkLoadedLib\|suspiciousLib\|injectedLib")
    if [[ -n "$result2" ]]; then
      add_finding "Injection" "MEDIUM" "HIGH" "Loaded library validation detected" "Enumerates and validates loaded dylibs"
    else
      add_finding "Injection" "LOW" "MEDIUM" "Dyld image enumeration detected" "Uses _dyld_image_count/_dyld_get_image_name (possible injection check)"
    fi
  fi

  # Check for MobileSubstrate/Substrate detection
  result=$(search_files "MobileSubstrate\|SubstrateLoader\|CydiaSubstrate\|substrate\|libsubstrate\|MSHookFunction\|MSHookMessageEx")
  if [[ -n "$result" ]]; then
    add_finding "Injection" "MEDIUM" "HIGH" "Substrate/Cydia Substrate detection found" "Checks for Substrate hooking framework"
  fi

  # Check for Frida detection
  result=$(search_files "frida\|FridaGadget\|frida-server\|frida-agent\|gum-js-loop\|linjector")
  if [[ -n "$result" ]]; then
    add_finding "Injection" "MEDIUM" "HIGH" "Frida instrumentation detection found" "Checks for Frida runtime injection"
  fi

  # Check for fishhook detection
  result=$(search_files "fishhook\|rebind_symbols\|original_.*_ptr")
  if [[ -n "$result" ]]; then
    add_finding "Injection" "LOW" "MEDIUM" "fishhook-related symbols detected" "May be used for hooking or hook detection"
  fi

  # Check for dlopen/dlsym monitoring
  result=$(search_files "dlopen.*monitor\|dlsym.*check\|checkDynamicLib\|validateDlopen")
  if [[ -n "$result" ]]; then
    add_finding "Injection" "MEDIUM" "MEDIUM" "Dynamic library loading monitoring detected" "Validates dlopen/dlsym calls"
  fi

  # Hardened runtime / library validation entitlement
  if [[ -f "$ANALYSIS_DIR/entitlements.plist" ]]; then
    result=$(grep -i "library-validation\|com.apple.security.cs.disable-library-validation" "$ANALYSIS_DIR/entitlements.plist" 2>/dev/null || true)
    if [[ -n "$result" ]]; then
      if echo "$result" | grep -q "disable-library-validation"; then
        add_finding "Injection" "MEDIUM" "HIGH" "Library validation DISABLED via entitlement" "com.apple.security.cs.disable-library-validation is set"
      else
        add_finding "Injection" "INFO" "HIGH" "Library validation entitlement present" "Enforces code signing for loaded libraries"
      fi
    fi
  fi

  echo
fi

# =====================================================================
# 5. Jailbreak Detection
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_JAILBREAK" == true ]]; then
  echo "--- Jailbreak Detection ---"

  # File-based checks
  JB_FILES=(
    "/Applications/Cydia.app"
    "/Library/MobileSubstrate"
    "/bin/bash"
    "/usr/sbin/sshd"
    "/etc/apt"
    "/private/var/lib/apt"
    "/usr/bin/ssh"
    "/usr/libexec/sftp-server"
    "/var/cache/apt"
    "/var/lib/cydia"
    "/var/tmp/cydia.log"
    "/Applications/Sileo.app"
    "/Applications/Zebra.app"
    "/var/jb"
    "/var/binpack"
    "/.bootstrapped"
    "/usr/lib/TweakInject"
    "/Library/TweakInject"
    "/var/mobile/Library/Preferences/com.saurik"
  )

  jb_file_hits=0
  for jb_path in "${JB_FILES[@]}"; do
    result=$(search_binary_strings "$jb_path")
    if [[ -n "$result" ]]; then
      jb_file_hits=$((jb_file_hits + 1))
    fi
  done

  if [[ "$jb_file_hits" -gt 5 ]]; then
    add_finding "Jailbreak" "INFO" "HIGH" "Comprehensive jailbreak file path detection ($jb_file_hits paths checked)" "Checks for Cydia, Sileo, Zebra, SSH, apt, Substrate"
  elif [[ "$jb_file_hits" -gt 0 ]]; then
    add_finding "Jailbreak" "INFO" "MEDIUM" "Basic jailbreak file path detection ($jb_file_hits paths checked)" "Checks some common jailbreak paths"
  fi

  # URL scheme checks (cydia://)
  result=$(search_files "cydia://\|sileo://\|zbra://\|filza://")
  if [[ -n "$result" ]]; then
    add_finding "Jailbreak" "INFO" "HIGH" "Jailbreak URL scheme detection (cydia://, sileo://, etc.)" "canOpenURL checks for jailbreak apps"
  fi

  # Sandbox escape detection (fork/system)
  result=$(search_files "fork()\|system()\|popen(")
  if [[ -n "$result" ]]; then
    result2=$(search_files "canFork\|forkTest\|sandboxCheck\|testSandbox")
    if [[ -n "$result2" ]]; then
      add_finding "Jailbreak" "INFO" "HIGH" "Sandbox integrity check (fork test) detected" "Tests if fork() succeeds (fails in sandbox)"
    fi
  fi

  # Symbolic link checks
  result=$(search_files "lstat\|readlink\|isSymlink\|symbolicLink.*Applications\|checkSymlink")
  if [[ -n "$result" ]]; then
    add_finding "Jailbreak" "INFO" "MEDIUM" "Symbolic link validation detected" "Checks for symlinked system paths (jailbreak indicator)"
  fi

  # Write test to protected paths
  result=$(search_files "writeToFile.*private\|canWrite.*system\|testWrite.*protected\|writeTest")
  if [[ -n "$result" ]]; then
    add_finding "Jailbreak" "INFO" "MEDIUM" "Protected path write test detected" "Attempts to write to system paths to test jailbreak"
  fi

  # Environment variable checks
  result=$(search_files "DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH\|DYLD_FRAMEWORK_PATH")
  if [[ -n "$result" ]]; then
    add_finding "Jailbreak" "INFO" "MEDIUM" "DYLD environment variable checks detected" "Checks for suspicious DYLD_* environment variables"
  fi

  # Known jailbreak detection frameworks
  result=$(search_files "IOSSecuritySuite\|DTTJailbreakDetection\|JailbreakDetect\|isJailBroken\|isJailbroken\|jailbreakStatus")
  if [[ -n "$result" ]]; then
    add_finding "Jailbreak" "INFO" "HIGH" "Jailbreak detection library/framework detected" "Uses dedicated jailbreak detection SDK"
  fi

  echo
fi

# =====================================================================
# 6. Binary Encryption (FairPlay DRM)
# =====================================================================

if [[ "$DO_ALL" == true ]] || [[ "$DO_ENCRYPTION" == true ]]; then
  echo "--- Binary Encryption Analysis ---"

  # Check LC_ENCRYPTION_INFO in load commands
  if [[ -f "$ANALYSIS_DIR/load-commands.txt" ]]; then
    result=$(grep -A4 "LC_ENCRYPTION_INFO" "$ANALYSIS_DIR/load-commands.txt" 2>/dev/null || true)
    if [[ -n "$result" ]]; then
      cryptid=$(echo "$result" | grep -i "cryptid" | awk '{print $2}' || echo "unknown")
      if [[ "$cryptid" == "1" ]]; then
        add_finding "Encryption" "HIGH" "HIGH" "Binary is FairPlay DRM encrypted (cryptid=1)" "Binary must be decrypted before static analysis; class-dump output may be incomplete"
      elif [[ "$cryptid" == "0" ]]; then
        add_finding "Encryption" "INFO" "HIGH" "Binary has LC_ENCRYPTION_INFO but is decrypted (cryptid=0)" "Previously encrypted but now decrypted (from decrypted dump)"
      else
        add_finding "Encryption" "MEDIUM" "MEDIUM" "LC_ENCRYPTION_INFO present (cryptid=$cryptid)" "Check if binary needs decryption"
      fi
    else
      add_finding "Encryption" "INFO" "HIGH" "No FairPlay DRM encryption detected" "Binary is not encrypted; full static analysis possible"
    fi
  fi

  # Check directly on binary (otool macOS, ipsw cross-platform fallback)
  if [[ -n "$BINARY_FILE" ]] && [[ -f "$BINARY_FILE" ]]; then
    crypt_info=$(macho_load_commands "$BINARY_FILE" | grep -A4 "LC_ENCRYPTION_INFO" || true)
    if [[ -n "$crypt_info" ]]; then
      cryptid=$(echo "$crypt_info" | grep "cryptid" | awk '{print $2}' || echo "")
      if [[ "$cryptid" == "1" ]]; then
        add_finding "Encryption" "HIGH" "HIGH" "Direct binary check: FairPlay encrypted (cryptid=1)" "Use frida-ios-dump, Clutch, or bfdecrypt to decrypt"
      fi
    fi
  fi

  echo
fi

# =====================================================================
# Summary
# =====================================================================

echo "=== Protection Detection Summary ==="
echo "Total findings: ${#FINDINGS[@]}"
echo

# Count by type (portable: no associative arrays, for bash 3.2 on macOS)
echo "By type:"
if [[ ${#FINDING_TYPES[@]} -gt 0 ]]; then
  while IFS= read -r t; do
    c=$(printf '%s\n' "${FINDING_TYPES[@]}" | grep -cxF "$t")
    printf "  %-20s %d\n" "$t" "$c"
  done < <(printf '%s\n' "${FINDING_TYPES[@]}" | sort -u)
fi
echo

# Protection score
score=0
for i in "${!FINDINGS[@]}"; do
  confidence="${FINDING_CONFIDENCES[$i]}"
  case "${FINDING_TYPES[$i]}" in
    "Anti-Debug")  [[ "$confidence" != "LOW" ]] && score=$((score + 2)) ;;
    "Injection")   [[ "$confidence" != "LOW" ]] && score=$((score + 2)) ;;
    "Jailbreak")   [[ "$confidence" != "LOW" ]] && score=$((score + 1)) ;;
    "Integrity")   [[ "$confidence" != "LOW" ]] && score=$((score + 2)) ;;
    "Obfuscation") [[ "$confidence" != "LOW" ]] && score=$((score + 1)) ;;
    "Encryption")  ;; # Don't count encryption in protection score
  esac
done

echo "Protection score: $score/20"
if [[ "$score" -ge 15 ]]; then
  echo "Assessment: HEAVILY PROTECTED — Expect significant reverse engineering resistance"
elif [[ "$score" -ge 10 ]]; then
  echo "Assessment: WELL PROTECTED — Multiple protection layers present"
elif [[ "$score" -ge 5 ]]; then
  echo "Assessment: MODERATELY PROTECTED — Some protections in place"
elif [[ "$score" -gt 0 ]]; then
  echo "Assessment: LIGHTLY PROTECTED — Basic protections only"
else
  echo "Assessment: UNPROTECTED — No anti-tampering or anti-debug protections detected"
fi

# =====================================================================
# Markdown report
# =====================================================================

if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# iOS Protection & Anti-Tampering Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Total findings**: ${#FINDINGS[@]}"
    echo "**Protection score**: $score/20"
    echo

    # Summary table
    echo "## Findings Summary"
    echo
    echo "| Type | Severity | Confidence | Description |"
    echo "|------|----------|------------|-------------|"
    for i in "${!FINDINGS[@]}"; do
      echo "| ${FINDING_TYPES[$i]} | ${FINDING_SEVERITIES[$i]} | ${FINDING_CONFIDENCES[$i]} | ${FINDINGS[$i]} |"
    done
    echo

    # Detailed sections
    for section_type in "Obfuscation" "Integrity" "Anti-Debug" "Injection" "Jailbreak" "Encryption"; do
      has_findings=false
      for i in "${!FINDINGS[@]}"; do
        if [[ "${FINDING_TYPES[$i]}" == "$section_type" ]]; then
          has_findings=true
          break
        fi
      done

      if [[ "$has_findings" == true ]]; then
        echo "## $section_type"
        echo
        for i in "${!FINDINGS[@]}"; do
          if [[ "${FINDING_TYPES[$i]}" == "$section_type" ]]; then
            echo "### ${FINDINGS[$i]}"
            echo
            echo "- **Severity**: ${FINDING_SEVERITIES[$i]}"
            echo "- **Confidence**: ${FINDING_CONFIDENCES[$i]}"
            echo "- **Evidence**: ${FINDING_EVIDENCES[$i]}"
            echo
          fi
        done
      fi
    done

    echo "## Bypass Considerations"
    echo
    echo "For authorized security testing, these protections may need to be considered:"
    echo
    for i in "${!FINDINGS[@]}"; do
      case "${FINDING_TYPES[$i]}" in
        "Anti-Debug")
          echo "- **${FINDINGS[$i]}**: May need to patch or hook the detection routine"
          ;;
        "Jailbreak")
          echo "- **${FINDINGS[$i]}**: Tools like Liberty Lite or A-Bypass can help during testing"
          ;;
        "Injection")
          echo "- **${FINDINGS[$i]}**: May block Frida/Substrate; consider alternative approaches"
          ;;
        "Encryption")
          if echo "${FINDINGS[$i]}" | grep -q "encrypted"; then
            echo "- **${FINDINGS[$i]}**: Decrypt with frida-ios-dump before analysis"
          fi
          ;;
      esac
    done
    echo
    echo "---"
    echo "_Report generated by ios-reverse-engineering-skill_"
  } > "$REPORT_FILE"
  echo
  echo "Report saved to: $REPORT_FILE"
fi
