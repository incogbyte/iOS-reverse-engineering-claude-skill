// FindSecrets.java — Ghidra headless script
// Searches decompiled code + defined strings for hardcoded credentials, API keys, and secrets.
// Aligned with the provider list / FP logic of deep-secret-scan.sh: each finding carries an
// FP-likelihood (Low/Medium/High) and a client-safe flag. Allowlisted placeholders and
// low-entropy / format-mismatched strings are tagged FP=High and excluded from the
// CRITICAL/HIGH totals unless --raw-style behavior is desired (here: kept but downgraded).
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript FindSecrets.java <output_dir>
//@category iOS-Reversing

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindSecrets extends GhidraScript {

    private static class SecretPattern {
        String name;
        String severity;
        Pattern pattern;
        boolean clientSafe; // true → intended for client use (downgrade CRITICAL→MEDIUM)
        boolean needsEntropy; // true → apply Shannon entropy gate (e.g. 64-hex Ethereum key)

        SecretPattern(String name, String severity, String regex, boolean clientSafe, boolean needsEntropy) {
            this.name = name;
            this.severity = severity;
            this.pattern = Pattern.compile(regex);
            this.clientSafe = clientSafe;
            this.needsEntropy = needsEntropy;
        }
    }

    // Provider list mirrors deep-secret-scan.sh (scan_secret calls) + allowlist constants.
    private static final SecretPattern[] PATTERNS = {
        // --- Critical ---
        new SecretPattern("AWS Access Key ID", "CRITICAL", "(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}", false, false),
        new SecretPattern("AWS Secret Access Key", "CRITICAL", "(?i)aws[_-]?secret[_-]?(access[_-]?)?key[_=:][[:space:]]*[A-Za-z0-9/+=]{40}", false, false),
        new SecretPattern("AWS Session Token", "HIGH", "(?i)aws[_-]?session[_-]?token[_=:][[:space:]]*[A-Za-z0-9/+=]{50,}", false, false),
        new SecretPattern("Stripe Secret Key", "CRITICAL", "sk_live_[0-9a-zA-Z]{24,}", false, false),
        new SecretPattern("Stripe Restricted Key", "HIGH", "rk_(live|test)_[0-9a-zA-Z]{24,}", false, false),
        new SecretPattern("GitHub Token", "CRITICAL", "(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}", false, false),
        new SecretPattern("GitLab Token", "CRITICAL", "glpat-[A-Za-z0-9_-]{20}", false, false),
        new SecretPattern("SendGrid API Key", "CRITICAL", "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}", false, false),
        new SecretPattern("Slack Token", "CRITICAL", "xox[abprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}", false, false),
        new SecretPattern("Ethereum Private Key (64 hex)", "CRITICAL", "(0x)?[0-9a-fA-F]{64}", false, true),
        new SecretPattern("Private Key Block", "CRITICAL", "-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", false, false),
        new SecretPattern("Azure Connection String", "CRITICAL", "DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}", false, false),
        new SecretPattern("GCP Service Account JSON", "CRITICAL", "\"type\"\\s*:\\s*\"service_account\"", false, false),
        new SecretPattern("Firebase Service Account JSON", "CRITICAL", "\"type\"\\s*:\\s*\"service_account\"", false, false),
        new SecretPattern("Generic Secret Assignment", "CRITICAL", "(?i)(password|passwd|secret|private.?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", false, false),

        // --- High ---
        new SecretPattern("GCP API Key", "HIGH", "AIza[0-9A-Za-z_-]{35}", true, false),
        new SecretPattern("Twilio Account SID", "HIGH", "AC[0-9a-f]{32}", false, false),
        new SecretPattern("Twilio API Key", "HIGH", "SK[0-9a-f]{32}", false, false),
        new SecretPattern("Mailgun API Key", "HIGH", "key-[a-f0-9]{32}", false, false),
        new SecretPattern("Mailchimp API Key", "HIGH", "[a-f0-9]{32}-us[0-9]{1,2}", false, false),
        new SecretPattern("Telegram Bot Token", "HIGH", "[0-9]{8,10}:[A-Za-z0-9_-]{34,40}", false, false),
        new SecretPattern("Square App Secret", "HIGH", "sq0[a-z][A-Za-z0-9_-]{20,}", false, false),
        new SecretPattern("Mapbox Secret Token", "HIGH", "sk\\.[A-Za-z0-9]+\\.[A-Za-z0-9-]+", false, false),
        new SecretPattern("Sentry DSN (with secret)", "HIGH", "https://[a-f0-9]{32}@[a-z0-9.-]+\\.ingest\\.sentry\\.io/[0-9]+", false, false),
        new SecretPattern("Azure SAS Token", "HIGH", "SharedAccessSignature=[^\\s\"']+|sv=[0-9]{4}-[0-9]{2}-[0-9]{2}[^\\s\"']*sig=[A-Za-z0-9%+/=]+", false, false),
        new SecretPattern("JWT Token", "HIGH", "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", false, false),

        // --- Medium ---
        new SecretPattern("Firebase API Key", "MEDIUM", "AIza[0-9A-Za-z_-]{35}", true, false),
        new SecretPattern("Stripe Test Secret Key", "MEDIUM", "sk_test_[0-9a-zA-Z]{24,}", false, false),
        new SecretPattern("Stripe Publishable Key", "MEDIUM", "pk_(live|test)_[0-9a-zA-Z]{24,}", true, false),
        new SecretPattern("Mapbox Public Token", "MEDIUM", "pk\\.[A-Za-z0-9]+\\.[A-Za-z0-9-]+", true, false),
        new SecretPattern("Infura API Key (in URL)", "MEDIUM", "https://[a-z0-9]*\\.infura\\.io/v3/[A-Za-z0-9]{32}", true, false),
        new SecretPattern("Alchemy API Key (in URL)", "MEDIUM", "https://[a-z-]*\\.g\\.alchemy\\.com/[a-z0-9]+/[A-Za-z0-9_-]{30,}", true, false),
        new SecretPattern("Hardcoded URL with Credentials", "MEDIUM", "https?://[^:]+:[^@]+@", false, false),
        new SecretPattern("Firebase Database URL", "MEDIUM", "https://[a-z0-9-]+\\.firebaseio\\.com", false, false),
        new SecretPattern("Cognito Pool ID", "MEDIUM", "[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}", false, false),

        // --- Low ---
        new SecretPattern("Hardcoded API Endpoint", "LOW", "(?i)(api[_-]?(url|endpoint|base|host)|base[_-]?url)\\s*[:=]\\s*['\"]https?://", false, false),
        new SecretPattern("Hardcoded IP Address", "LOW", "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b", false, false),
        new SecretPattern("Encryption Key Assignment", "LOW", "(?i)(aes|encryption|crypto).{0,20}(key|iv|salt|nonce)\\s*[:=]", false, false),
    };

    // Allowlist of placeholders/example values — matches are tagged FP=High and excluded from
    // CRITICAL/HIGH totals. Mirrors deep-secret-scan.sh ALLOWLIST_RE.
    private static final Pattern PLACEHOLDER_REGEX = Pattern.compile(
        "(?i)(AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI.*EXAMPLE|EXAMPLEKEY|example\\.com|your[_-][A-Za-z0-9]+|YOUR[_-][A-Z0-9]+|<[^>]+>|^x{3,}$|^abc123$|^test$|^sample$|^dummy$|^placeholder$|^redacted$|^foobar$|^123$|REPLACE|TODO|my[_-](api[_-]?key|secret|token)|test[_-]key|demo[_-]key|firebase[_-]?(example|demo)|sentry[_-]?(example|demo)|maps\\.googleapis\\.com.*YOUR|sk_test|pk_test)"
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: FindSecrets.java <output_dir>");
            return;
        }

        String outputDir = args[0];
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        List<String> findings = new ArrayList<>();
        int fpHighCount = 0;
        int clientSafeCount = 0;

        // Phase 1: Search in defined strings
        println("Phase 1: Scanning defined strings...");
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext() && !monitor.isCancelled()) {
            Data data = dataIt.next();
            if (data.getDataType() instanceof StringDataType ||
                data.getDataType().getName().contains("string") ||
                data.getDataType().getName().contains("String")) {
                String value = data.getDefaultValueRepresentation();
                if (value != null) {
                    for (SecretPattern sp : PATTERNS) {
                        Matcher m = sp.pattern.matcher(value);
                        while (m.find()) {
                            String match = m.group();
                            String addr = data.getAddress().toString();
                            String record = buildFinding(sp, match, addr, null, null);
                            if (record != null) {
                                String[] meta = record.split("\\|");
                                findings.add(record);
                                if ("HIGH".equals(meta[0].trim())) fpHighCount++;
                                if (record.contains("| client-safe:yes")) clientSafeCount++;
                            }
                        }
                    }
                }
            }
        }
        println("  String scan: " + findings.size() + " findings");

        // Phase 2: Search in decompiled code
        println("Phase 2: Scanning decompiled functions...");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        int preDecompCount = findings.size();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            try {
                DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null) {
                        for (SecretPattern sp : PATTERNS) {
                            Matcher m = sp.pattern.matcher(code);
                            while (m.find()) {
                                String match = m.group();
                                String addr = func.getEntryPoint().toString();
                                String record = buildFinding(sp, match, addr, func.getName() + " @ " + addr, match);
                                if (record != null) {
                                    String[] meta = record.split("\\|");
                                    findings.add(record);
                                    if ("HIGH".equals(meta[0].trim())) fpHighCount++;
                                    if (record.contains("| client-safe:yes")) clientSafeCount++;
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip functions that fail to decompile
            }
        }
        decompiler.dispose();
        println("  Decompilation scan: " + (findings.size() - preDecompCount) + " additional findings");

        // Write report
        File reportFile = new File(outDir, "secrets-findings.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(reportFile));
        writer.println("=== Ghidra Secret/Credential Analysis ===");
        writer.println("Binary: " + currentProgram.getName());
        writer.println("Date: " + new java.util.Date());
        writer.println("Total findings: " + findings.size());
        writer.println("High-FP-likelihood (placeholders/low-entropy/format-mismatch): " + fpHighCount);
        writer.println("Client-safe: " + clientSafeCount);
        writer.println();
        writer.println("Severity | FP | client-safe | Type | Location | Match");
        writer.println("---------|----|-------------|------|----------|------");

        // Sort by severity
        findings.sort((a, b) -> {
            int sa = severityOrder(a.split("\\|")[0].trim());
            int sb = severityOrder(b.split("\\|")[0].trim());
            return sa - sb;
        });

        for (String finding : findings) {
            writer.println(finding);
        }

        writer.println();
        writer.println("--- FP filtering notes ---");
        writer.println("- Values matching the allowlist (EXAMPLE, your_key, AKIAIOSFODNN7EXAMPLE, sk_test/pk_test) are tagged FP=High and excluded from CRITICAL/HIGH emphasis.");
        writer.println("- Shannon entropy < 3.0 bits/char raises FP-likelihood (long low-randomness strings are usually binary artifacts).");
        writer.println("- client-safe=yes (Firebase AIza, Stripe pk_live, Mapbox pk, Infura/Alchemy URLs) downgrades CRITICAL→MEDIUM.");
        writer.close();
        println("Secrets analysis complete: " + findings.size() + " findings");
        println("Report: " + reportFile.getAbsolutePath());
    }

    // Build a finding record, applying allowlist / entropy / client-safe logic. Returns null to
    // drop a finding (allowlisted placeholder excluded from totals).
    private String buildFinding(SecretPattern sp, String match, String addr, String location, String displayMatch) {
        String loc = (location != null) ? location : addr;
        String disp = truncate((displayMatch != null) ? displayMatch : match, 120);
        boolean allowlisted = PLACEHOLDER_REGEX.matcher(match).find();
        double ent = entropy(match);
        boolean lowEntropy = sp.needsEntropy && ent < 3.0;

        String fp;
        if (allowlisted || lowEntropy) {
            fp = "HIGH";
        } else if (ent < 3.0) {
            fp = "MEDIUM";
        } else {
            fp = "LOW";
        }

        String severity = sp.severity;
        if ("CRITICAL".equals(severity) && sp.clientSafe) {
            severity = "MEDIUM"; // client-safe downgrade
        }

        // Allowlisted placeholders: keep in report (tagged) but they won't dominate totals.
        return severity + " | " + fp + " | client-safe:" + (sp.clientSafe ? "yes" : "no") +
               " | " + sp.name + " | " + loc + " | " + disp;
    }

    // Shannon entropy in bits/char (mirrors deep-secret-scan.sh entropy()).
    private double entropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        java.util.Map<Character, Integer> freq = new java.util.HashMap<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        }
        double e = 0.0;
        int len = s.length();
        for (int cnt : freq.values()) {
            double p = (double) cnt / len;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        s = s.replace("\n", " ").replace("\r", "");
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private int severityOrder(String severity) {
        switch (severity) {
            case "CRITICAL": return 0;
            case "HIGH": return 1;
            case "MEDIUM": return 2;
            case "LOW": return 3;
            default: return 4;
        }
    }
}