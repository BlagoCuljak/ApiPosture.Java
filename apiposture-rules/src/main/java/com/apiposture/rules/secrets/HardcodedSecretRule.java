package com.apiposture.rules.secrets;

import com.apiposture.core.models.Finding;
import com.apiposture.core.models.Severity;
import com.apiposture.core.models.SourceLocation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AP201: Hardcoded secret.
 *
 * <p>High-precision detector limited to provider-prefixed credentials (cloud keys, tokens,
 * webhooks, PEM private keys). Generic heuristics such as {@code password=} are intentionally
 * not supported because of their false-positive rate.
 */
public class HardcodedSecretRule {

    public static final String ID = "AP201";
    public static final String NAME = "Hardcoded secret";

    private static final long MAX_FILE_BYTES = 2L * 1024 * 1024;

    private record SecretPattern(String name, Pattern regex) {}

    private static final List<SecretPattern> PATTERNS = List.of(
            new SecretPattern("AWS access key ID", Pattern.compile("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b")),
            new SecretPattern("GCP API key", Pattern.compile("\\bAIza[0-9A-Za-z\\-_]{35}\\b")),
            new SecretPattern("GitHub token", Pattern.compile("\\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\\b")),
            new SecretPattern("GitHub fine-grained token", Pattern.compile("\\bgithub_pat_[0-9A-Za-z_]{82}\\b")),
            new SecretPattern("GitLab personal access token", Pattern.compile("\\bglpat-[0-9A-Za-z\\-_]{20,}\\b")),
            new SecretPattern("Stripe live secret key", Pattern.compile("\\b(sk|rk)_live_[0-9A-Za-z]{24,}\\b")),
            new SecretPattern("Slack token", Pattern.compile("\\bxox[baprs]-[0-9A-Za-z\\-]{10,}\\b")),
            new SecretPattern("Slack webhook", Pattern.compile(
                    "https://hooks\\.slack\\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24}")),
            new SecretPattern("SendGrid API key",
                    Pattern.compile("\\bSG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}\\b")),
            new SecretPattern("npm token", Pattern.compile("\\bnpm_[0-9A-Za-z]{36}\\b")),
            new SecretPattern("DigitalOcean token", Pattern.compile("\\bdop_v1_[0-9a-f]{64}\\b")),
            new SecretPattern("PEM private key", Pattern.compile(
                    "-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"))
    );

    private static final List<String> PLACEHOLDER_MARKERS = List.of(
            "example", "xxxx", "your_", "your-", "<", ">", "${", "{{",
            "changeme", "dummy", "fake", "sample", "placeholder", "redacted");

    private static final Set<String> EXCLUDED_DIRS = Set.of(
            "test", "tests", "spec", "specs", "__tests__", "fixtures", "testdata",
            "samples", "examples", "docs", "node_modules", "vendor", "target", "build");

    public String getId() {
        return ID;
    }

    public String getName() {
        return NAME;
    }

    public Severity getDefaultSeverity() {
        return Severity.HIGH;
    }

    /**
     * Whether a file (path relative to the scan root) should be skipped entirely.
     */
    public static boolean isExcludedPath(Path relativePath) {
        int count = relativePath.getNameCount();
        for (int i = 0; i < count - 1; i++) {
            if (EXCLUDED_DIRS.contains(relativePath.getName(i).toString().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        String name = relativePath.getFileName().toString();
        String lower = name.toLowerCase(Locale.ROOT);
        return name.endsWith("Test.java") || name.endsWith("Tests.java") || name.endsWith("IT.java")
                || lower.endsWith(".lock") || lower.equals("package-lock.json")
                || lower.endsWith(".min.js") || lower.endsWith(".min.css");
    }

    /**
     * True if the matched value looks like a placeholder rather than a real credential.
     */
    public static boolean isPlaceholder(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        for (String marker : PLACEHOLDER_MARKERS) {
            if (lower.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Redact a secret to its first 4 characters followed by an ellipsis.
     */
    public static String redact(String value) {
        return value.substring(0, Math.min(4, value.length())) + "…";
    }

    /**
     * Scan one file. Returns an empty list if the file is excluded, unreadable or clean.
     *
     * @param root scan root, used to evaluate path exclusions
     * @param file file to scan
     */
    public List<Finding> scanFile(Path root, Path file) {
        Path absRoot = root.toAbsolutePath().normalize();
        Path absFile = file.toAbsolutePath().normalize();
        Path relative = absFile.startsWith(absRoot) ? absRoot.relativize(absFile) : absFile.getFileName();
        if (isExcludedPath(relative)) {
            return List.of();
        }
        try {
            if (Files.size(absFile) > MAX_FILE_BYTES) {
                return List.of();
            }
            String content = Files.readString(absFile, StandardCharsets.UTF_8);
            return scanContent(absFile.toString(), content);
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
    }

    /**
     * Scan text content (no path exclusion applied). One finding per (line, secret type).
     */
    public List<Finding> scanContent(String filePath, String content) {
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        String[] lines = content.split("\r\n|\r|\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.length() < 16 || line.length() > 5000) {
                continue;
            }
            for (SecretPattern p : PATTERNS) {
                Matcher m = p.regex().matcher(line);
                while (m.find()) {
                    String value = m.group();
                    if (isPlaceholder(value) || !seen.add((i + 1) + "|" + p.name())) {
                        continue;
                    }
                    findings.add(Finding.builder()
                            .ruleId(ID)
                            .ruleName(NAME)
                            .severity(Severity.HIGH)
                            .message("Hardcoded " + p.name() + " detected (" + redact(value) + ")")
                            .location(new SourceLocation(filePath, i + 1, m.start() + 1))
                            .recommendation("Remove the secret from source, rotate it, and load it from "
                                    + "an environment variable or a secrets manager.")
                            .build());
                }
            }
        }
        return findings;
    }
}
