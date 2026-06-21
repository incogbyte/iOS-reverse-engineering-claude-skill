#!/usr/bin/env bash
# lib/plist.sh — portable plist readers (source this file, do not execute)
#
# Works on macOS and Linux. macOS tools (plutil, PlistBuddy) are tried first; when absent the
# cross-platform fallbacks (python3 plistlib, which handles binary plists natively, then
# libplist's plistutil) are used. This lets the skill read Info.plist / entitlements.plist /
# PrivacyInfo.xcprivacy on Linux without any macOS-only tools.
#
# Provided functions:
#   plist_val  <key> [plist]   -> echoes a scalar value for a (dotted) key path a.b.c, "" if absent
#   plist_json [plist]         -> echoes the whole plist as JSON (for array/scheme extraction)
#
# A "scalar" here means a string/number/bool printed in plutil-raw style (true/false/<string>);
# for arrays/dicts use plist_json and parse externally.

export LC_ALL=C

# Internal: resolve a dotted key path against a nested dict, returning "" if any step is missing.
_plist_walk() {
  local key="$1" plist="$2"
  python3 - "$plist" "$key" <<'PY' 2>/dev/null || true
import plistlib, sys, json
path = sys.argv[2].split(".")
try:
    with open(sys.argv[1], "rb") as f:
        d = plistlib.load(f)
except Exception:
    sys.exit(0)
v = d
for p in path:
    if isinstance(v, dict) and p in v:
        v = v[p]
    else:
        sys.exit(0)
if isinstance(v, bool):
    print("true" if v else "false")
elif v is None:
    print("")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
PY
}

# plist_val <key> [plist] -> scalar value ("" if absent or no reader available)
plist_val() {
  local key="$1" plist="${2:-${ANALYSIS_DIR:-.}/Info.plist}"
  [[ -f "$plist" ]] || { echo ""; return; }

  if command -v plutil >/dev/null 2>&1; then
    # plutil -extract supports dotted keys natively; raw prints the scalar. rc=0 if the key
    # exists (even for false/empty), rc=1 if absent.
    local v
    v=$(plutil -extract "$key" raw "$plist" 2>/dev/null) && { echo "$v"; return; }
  fi

  if command -v /usr/libexec/PlistBuddy >/dev/null 2>&1; then
    # "a.b.c" -> ":a:b:c" (PlistBuddy key path), no sed dependency
    /usr/libexec/PlistBuddy -c "Print :${key//./:}" "$plist" 2>/dev/null || true
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    _plist_walk "$key" "$plist"
    return
  fi

  if command -v plistutil >/dev/null 2>&1; then
    # libplist: convert to JSON then pull the leaf with python3-less grep (best-effort, scalar only)
    local json leaf
    json=$(plistutil -i "$plist" -f json 2>/dev/null) || true
    [[ -n "$json" ]] || { echo ""; return; }
    leaf=$(echo "$json" | python3 -c 'import sys,json; d=json.load(sys.stdin); v=d
for p in sys.argv[1].split("."):
    v=v.get(p) if isinstance(v,dict) else None
    if v is None: break
print("" if v is None else (str(v).lower() if isinstance(v,bool) else v))' "$key" 2>/dev/null) || true
    echo "$leaf"
    return
  fi

  echo ""
}

# plist_json [plist] -> whole plist as JSON (compact)
plist_json() {
  local plist="${1:-${ANALYSIS_DIR:-.}/Info.plist}"
  [[ -f "$plist" ]] || { echo ""; return; }

  if command -v plutil >/dev/null 2>&1; then
    plutil -convert json -o - "$plist" 2>/dev/null || true
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import plistlib,sys,json
try:
    with open(sys.argv[1],"rb") as f: d=plistlib.load(f)
    print(json.dumps(d))
except Exception: pass' "$plist" 2>/dev/null || true
    return
  fi

  if command -v plistutil >/dev/null 2>&1; then
    plistutil -i "$plist" -f json 2>/dev/null || true
    return
  fi

  echo ""
}