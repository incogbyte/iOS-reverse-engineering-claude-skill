# iOS Reverse Engineering Skill for Claude Code

A comprehensive [Claude Code skill](https://docs.anthropic.com/en/docs/claude-code/skills) that enables Claude to extract, analyze, and reverse engineer iOS applications. It processes IPA files, .app bundles, Mach-O binaries, dynamic libraries, and frameworks — producing structured documentation of APIs, security findings, embedded secrets, SDK inventories, and protection assessments.

## Features

- **IPA/App Extraction** — Unpack IPA archives and .app bundles, dump Objective-C/Swift class headers via `ipsw class-dump`, extract Info.plist, entitlements, embedded frameworks, and string constants
- **API Endpoint Discovery** — Find HTTP endpoints across URLSession, Alamofire, Moya, AFNetworking, GraphQL, and WebSocket patterns
- **Call Flow Tracing** — Follow execution paths from ViewControllers through ViewModels/Presenters down to the networking layer
- **Security Auditing** — Scan for ATS exceptions, certificate pinning issues, weak crypto, keychain misuse, jailbreak detection, debug artifacts, insecure deserialization, XXE, and Zip Slip
- **Cloud Credential Scanning** — Deep-scan for leaked API keys and secrets from Firebase, AWS, GCP, Azure, Stripe, Twilio, SendGrid, and more — with LLM-assisted risk classification
- **Deep Binary Reversing** — Decompile functions, trace cross-references, and analyze crypto/auth/network code using radare2, rizin, or Ghidra headless
- **SDK Fingerprinting** — Identify all embedded third-party SDKs, detect versions, and cross-reference with known CVEs
- **Protection Detection** — Detect obfuscation tools, anti-debugging, dylib injection prevention, integrity checks, jailbreak detection, and FairPlay DRM encryption

## Requirements

- **macOS** with Xcode Command Line Tools (provides `otool`, `strings`, `plutil`, `codesign`)
- **[ipsw](https://github.com/blacktop/ipsw)** — Required. Provides class-dump and Mach-O analysis (`brew install blacktop/tap/ipsw`)
- **[radare2](https://github.com/radareorg/radare2)** or **[rizin](https://github.com/rizinorg/rizin)** — Recommended for deep binary analysis
- **[Ghidra](https://ghidra-sre.org/)** — Optional. Enables advanced headless decompilation with included Java scripts

> Linux is supported for static analysis of already-extracted files only.

The skill includes dependency check and auto-install scripts that handle setup automatically.

## Installation

### As a Claude Code Skill (Recommended)

Add this repository as a skill in your Claude Code project:

```bash
claude mcp add-skill ios-reverse-engineering https://github.com/incogbyte/iOS-claude-skill.git
```

Or clone and add locally:

```bash
git clone https://github.com/incogbyte/iOS-claude-skill.git
```

Then reference the skill directory in your Claude Code configuration.

### Verify Dependencies

Once installed, Claude will automatically check and install dependencies when you first use the skill. You can also verify manually:

```bash
bash skills/ios-reverse-engineering/scripts/check-deps.sh
```

If anything is missing:

```bash
bash skills/ios-reverse-engineering/scripts/install-dep.sh <dependency>
```

## Usage

### Quick Start with the `/extract-ipa` Command

The skill provides a user-invocable slash command for the most common workflow:

```
/extract-ipa /path/to/MyApp.ipa
```

This will:
1. Check and install required dependencies
2. Extract the IPA and dump class headers
3. Analyze the app structure (Info.plist, entitlements, frameworks, architecture pattern)
4. Present a summary and offer next steps

### Supported Input Formats

| Format | Description |
|---|---|
| `.ipa` | iOS App Store package (ZIP archive containing `Payload/*.app`) |
| `.app` | Application bundle directory |
| Mach-O binary | Raw executable binary |
| `.dylib` | Dynamic library |
| `.framework` | Framework bundle |

### Extraction Options

```bash
# Basic extraction
/extract-ipa MyApp.ipa

# Custom output directory
/extract-ipa MyApp.ipa -o ./my-analysis

# Skip class-dump (faster, metadata only)
/extract-ipa MyApp.ipa --no-classdump

# Extract specific architecture from fat binaries
/extract-ipa MyApp.ipa --thin arm64

# Demangle Swift symbols
/extract-ipa MyApp.ipa --swift-demangle
```

### Analysis Phases

After extraction, you can ask Claude to perform any of the following analyses. Each phase builds on the extracted output.

#### 1. Structure Analysis
> "Analyze the app structure"

Reads Info.plist, entitlements, class-dump output, and embedded frameworks. Identifies the architecture pattern (MVC, MVVM, VIPER, Coordinator) and key classes.

#### 2. Call Flow Tracing
> "Trace the login flow from the UI to the network layer"

Follows execution paths: ViewController -> ViewModel/Presenter -> Service/Repository -> API Client -> URLSession/Alamofire. Maps dependency injection and service creation patterns.

#### 3. API Endpoint Extraction
> "Find all API endpoints and document them"

Searches for HTTP endpoints across all major networking libraries. Supports targeted searches:

- `--urlsession` — URLSession patterns only
- `--alamofire` — Alamofire/AFNetworking only
- `--graphql` — GraphQL operations
- `--websocket` — WebSocket connections
- `--auth` — Authentication patterns
- `--urls` — Hardcoded URLs
- `--swift-concurrency` — Combine/async-await patterns
- `--security` — Security-related patterns

Produces structured documentation for each endpoint including method, path, parameters, headers, response type, and call chain.

#### 4. Security Audit
> "Run a security audit on this app"

Scans for:
- App Transport Security (ATS) exceptions
- Disabled certificate pinning
- Hardcoded secrets and API keys
- Jailbreak detection mechanisms
- Weak cryptography (MD5, ECB mode, hardcoded IVs)
- Keychain misuse (`kSecAttrAccessibleAlways`)
- Debug artifacts and staging URLs

#### 5. Cloud Credential Scan
> "Scan for leaked API keys and credentials"

Deep-scans for credentials from 20+ cloud providers with targeted scan options:

- `--firebase` / `--aws` / `--gcp` / `--azure` — Cloud providers
- `--payments` — Stripe, PayPal, RevenueCat
- `--messaging` — Twilio, SendGrid, Slack, OneSignal
- `--analytics` — Sentry, Mixpanel, Amplitude, Segment
- `--jwt` — JWT tokens
- `--severity high` — Critical and high severity only

Each finding is classified by the LLM: service type, client-safety assessment, blast radius, false positive likelihood, validation steps, and remediation.

#### 6. Deep Binary Reversing
> "Decompile the authentication functions"

Uses radare2/rizin or Ghidra headless for binary-level analysis:

- `--quick` — Functions + strings + imports only
- `--secrets` — Focus on credential handling code
- `--network` — Focus on networking code
- `--crypto` — Focus on crypto implementations
- `--auth` — Focus on authentication logic
- `--decompile "sym.objc.AuthService.login"` — Decompile a specific function
- `--decompile-pattern "auth\|login\|token"` — Decompile matching functions
- `--xrefs "sym.imp.CCCrypt"` — Cross-references to a function
- `--callgraph "sym.objc.NetworkManager.request"` — Call graph visualization
- `--entropy` — Detect packing/encryption
- `--tool ghidra` — Force Ghidra headless with Java analysis scripts

Included Ghidra scripts:
- `DecompileAllFunctions.java` — Full or security-targeted decompilation
- `FindSecrets.java` — Credential and API key detection in decompiled code
- `ExportAPICalls.java` — Network API symbol tracing
- `ExportCryptoUsage.java` — Crypto function usage and weak pattern detection
- `ExportStringXrefs.java` — String cross-references categorized by type

#### 7. SDK Fingerprinting
> "Identify all third-party SDKs"

Detects embedded SDKs by framework names, linked libraries, class prefixes, SDK-specific strings, and symbols. Categories include: Networking, Analytics, Advertising, Authentication, Payments, Push Notifications, Maps, Social, Database, Cloud Storage, UI/UX, Security, Messaging, Crash Reporting, A/B Testing, Deep Linking, and AR/ML.

Options:
- `--check-cves` — Cross-reference detected SDK versions with known vulnerabilities
- `--verbose` — Show match details
- `--json` — JSON output for programmatic use

#### 8. Protection Detection
> "What protections does this app use?"

Detects anti-tampering mechanisms and outputs a protection score (0-20):

- `--obfuscation` — iXGuard, SwiftShield, OLLVM, Arxan, name obfuscation ratio, string encryption, control flow flattening
- `--debugger` — ptrace, sysctl, timing checks, exception ports, SIGTRAP handlers
- `--injection` — `__RESTRICT` segment, DYLD checks, library enumeration, Substrate/Frida detection
- `--integrity` — Runtime code signing, binary hash checks, team ID verification, receipt validation
- `--jailbreak` — File path checks, URL schemes, sandbox escape tests, environment variables
- `--encryption` — FairPlay DRM detection

| Score | Level |
|---|---|
| 15-20 | Heavily protected |
| 10-14 | Well protected |
| 5-9 | Moderately protected |
| 1-4 | Lightly protected |
| 0 | Unprotected |

#### 9. Static Vulnerability Audit
> "Audit this app for iOS vulnerability classes"

Hunts vulnerability *patterns* (not API calls or credential values) across 14 categories, each finding tagged with Severity, Confidence, and FP-likelihood so you can triage signal strength instead of treating every match as confirmed:

- `--storage` — UserDefaults secrets, weak Keychain accessibility, unencrypted local DBs, backup-exclusion absence, App-Group `UserDefaults` secret exposure
- `--webview` — `UIWebView`, file/universal access flags, JS-bridge handlers, TLS-bypassing auth challenge handlers
- `--deeplink` — custom URL schemes, tokens passed through deeplink callbacks, universal links
- `--crypto` — ECB mode, non-CSPRNG for tokens, MD5/SHA1, hardcoded IV/salt
- `--auth` — biometric bypass patterns, Sign in with Apple nonce absence
- `--logging` — secrets logged via `print`/`NSLog`/`os_log`
- `--network` — ATS exceptions, cleartext/insecure-WebSocket, custom trust bypass, third-party certificate-pinning misconfiguration (AFNetworking/TrustKit/Alamofire), permanently-persisted `URLCredential`
- `--privacy` — IDFA without ATT, sensitive pasteboard use, screen-capture and app-switcher/background-snapshot leaks, `LSApplicationQueriesSchemes` fingerprinting, Apple privacy manifest checks
- `--entitlements` — disabled library validation, app groups, shared keychain groups
- `--debug` — debug-gated insecure behavior, staging/internal URLs
- `--hardening` — Mach-O PIE / hardened-runtime flags
- `--injection` — NSPredicate/NSExpression, KVC, NSSelectorFromString/performSelector, stringWithFormat
- `--deserialization` — deprecated `NSKeyedUnarchiver`/`NSUnarchiver` APIs, missing `NSSecureCoding`
- `--parsing` — XXE (`NSXMLParser`/libxml2), Zip Slip in archive extraction
- `--all` — every category (default); `--severity LEVEL` filters by minimum severity; `--report FILE` exports Markdown

### Generating Reports

Most analysis scripts support `--report <file.md>` to generate structured Markdown reports:

```
"Extract the app, scan for secrets, fingerprint SDKs, detect protections, and generate reports for everything"
```

## Project Structure

```
iOS-claude-skill/
├── commands/
│   └── extract-ipa.md              # /extract-ipa slash command definition
├── skills/
│   └── ios-reverse-engineering/
│       ├── SKILL.md                 # Main skill definition and workflow
│       ├── scripts/
│       │   ├── check-deps.sh        # Dependency checker
│       │   ├── install-dep.sh       # Auto-installer for dependencies
│       │   ├── extract-ipa.sh       # IPA/app extraction and class-dump
│       │   ├── find-api-calls.sh    # API endpoint discovery
│       │   ├── deep-secret-scan.sh  # Cloud credential scanner
│       │   ├── reversing-analyze.sh # Binary reversing with r2/Ghidra
│       │   ├── detect-sdks.sh       # SDK fingerprinting
│       │   ├── detect-protections.sh# Protection detection
│       │   ├── audit-vulnerabilities.sh # Static vulnerability audit (14 categories)
│       │   ├── lib/
│       │   │   └── plist.sh         # Portable plist readers (macOS + Linux)
│       │   └── ghidra/              # Ghidra headless Java scripts
│       │       ├── DecompileAllFunctions.java
│       │       ├── FindSecrets.java
│       │       ├── ExportAPICalls.java
│       │       ├── ExportCryptoUsage.java
│       │       └── ExportStringXrefs.java
│       └── references/
│           ├── setup-guide.md       # Tool installation guide
│           ├── class-dump-usage.md  # ipsw class-dump reference
│           ├── api-extraction-patterns.md
│           ├── call-flow-analysis.md
│           ├── cloud-secrets-patterns.md
│           ├── reversing-tools-guide.md
│           ├── sdk-fingerprinting.md
│           ├── anti-tampering-patterns.md
│           └── vulnerability-patterns.md
├── LICENSE                          # Unlicense (public domain)
└── README.md
```

## Use Cases

- **Security research** — Audit iOS apps for vulnerabilities, leaked credentials, and weak crypto before responsible disclosure
- **Penetration testing** — Map attack surfaces, identify API endpoints, and assess protections during authorized engagements
- **CTF competitions** — Quickly extract and analyze iOS challenge binaries
- **Competitive analysis** — Understand how other apps are built, what SDKs they use, and how they structure their APIs
- **Compliance auditing** — Verify that apps meet security standards (ATS, cert pinning, keychain usage, data encryption)
- **Incident response** — Rapidly assess a suspicious IPA for malicious behavior, data exfiltration, or embedded malware

## License

This project is released into the public domain under the [Unlicense](https://unlicense.org). See [LICENSE](LICENSE) for details.
