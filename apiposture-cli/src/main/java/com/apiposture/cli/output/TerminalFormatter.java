package com.apiposture.cli.output;

import com.apiposture.core.models.*;
import org.fusesource.jansi.Ansi;

import java.util.Map;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Terminal output formatter with ANSI colors.
 */
public class TerminalFormatter implements OutputFormatter {

    private final boolean noColor;
    private final boolean noIcons;

    // Icons for severity levels
    private static final Map<Severity, String> SEVERITY_ICONS = Map.of(
            Severity.CRITICAL, "\u26D4",  // No entry sign
            Severity.HIGH, "\u2757",      // Exclamation mark
            Severity.MEDIUM, "\u26A0",    // Warning sign
            Severity.LOW, "\u2139",       // Info sign
            Severity.INFO, "\u2022"       // Bullet point
    );

    // Classification icons
    private static final Map<SecurityClassification, String> CLASSIFICATION_ICONS = Map.of(
            SecurityClassification.PUBLIC, "\uD83D\uDD13",           // Unlocked
            SecurityClassification.AUTHENTICATED, "\uD83D\uDD10",    // Locked with key
            SecurityClassification.ROLE_RESTRICTED, "\uD83D\uDD12",  // Locked
            SecurityClassification.POLICY_RESTRICTED, "\uD83D\uDEE1" // Shield
    );

    public TerminalFormatter(boolean noColor, boolean noIcons) {
        this.noColor = noColor;
        this.noIcons = noIcons;
    }

    @Override
    public String format(ScanResult result) {
        StringBuilder sb = new StringBuilder();

        // Header
        sb.append(formatHeader(result));
        sb.append("\n");

        // Summary section
        sb.append(formatSummary(result));
        sb.append("\n");

        // Endpoints section
        if (!result.endpoints().isEmpty()) {
            sb.append(formatEndpointsSection(result));
            sb.append("\n");
        }

        // Findings section
        if (!result.findings().isEmpty()) {
            sb.append(formatFindingsSection(result));
        }

        // Footer
        sb.append(formatFooter(result));

        return sb.toString();
    }

    private String formatHeader(ScanResult result) {
        String title = "ApiPosture Security Scan Report";
        String line = "=".repeat(title.length());

        if (noColor) {
            return title + "\n" + line + "\n";
        }

        return ansi()
                .bold().fgCyan().a(title).reset()
                .a("\n")
                .fgCyan().a(line).reset()
                .a("\n")
                .toString();
    }

    private String formatSummary(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");

        // Project info
        sb.append(colorize("Project: ", Ansi.Color.WHITE, true));
        sb.append(result.projectPath()).append("\n");

        sb.append(colorize("Files scanned: ", Ansi.Color.WHITE, true));
        sb.append(result.scannedFiles()).append("\n");

        sb.append(colorize("Duration: ", Ansi.Color.WHITE, true));
        sb.append(formatDuration(result.scanDuration().toMillis())).append("\n");

        sb.append("\n");

        // Counts
        sb.append(colorize("Endpoints found: ", Ansi.Color.WHITE, true));
        sb.append(result.getTotalEndpoints()).append("\n");

        sb.append(colorize("Findings: ", Ansi.Color.WHITE, true));
        sb.append(result.getTotalFindings()).append("\n");

        // Severity breakdown
        if (!result.findings().isEmpty()) {
            sb.append("\n");
            Map<Severity, Integer> counts = result.getSeverityCounts();

            for (Severity severity : new Severity[]{
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
                int count = counts.getOrDefault(severity, 0);
                if (count > 0) {
                    sb.append("  ");
                    sb.append(formatSeverity(severity));
                    sb.append(": ").append(count).append("\n");
                }
            }
        }

        return sb.toString();
    }

    private String formatEndpointsSection(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(colorize("\n--- Endpoints ---\n\n", Ansi.Color.CYAN, true));

        // Group by classification
        Map<SecurityClassification, java.util.List<Endpoint>> byClass = result.getEndpointsByClassification();

        for (SecurityClassification classification : SecurityClassification.values()) {
            java.util.List<Endpoint> endpoints = byClass.get(classification);
            if (endpoints == null || endpoints.isEmpty()) continue;

            sb.append(formatClassification(classification)).append(" (").append(endpoints.size()).append(")\n");

            for (Endpoint endpoint : endpoints) {
                sb.append("  ");
                sb.append(formatMethods(endpoint.methods()));
                sb.append(" ");
                sb.append(endpoint.route());
                sb.append(colorize(" [" + endpoint.controllerName() + "." + endpoint.methodName() + "]",
                        Ansi.Color.WHITE, false));
                sb.append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    private String formatFindingsSection(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(colorize("\n--- Findings ---\n\n", Ansi.Color.CYAN, true));

        for (Finding finding : result.findings()) {
            sb.append(formatFinding(finding));
            sb.append("\n");
        }

        return sb.toString();
    }

    private String formatFinding(Finding finding) {
        StringBuilder sb = new StringBuilder();

        // Severity and rule
        sb.append(formatSeverity(finding.severity()));
        sb.append(" ");
        sb.append(colorize("[" + finding.ruleId() + "]", Ansi.Color.YELLOW, false));
        sb.append(" ");
        sb.append(colorize(finding.ruleName(), Ansi.Color.WHITE, true));
        sb.append("\n");

        // Message
        sb.append("   ").append(finding.message()).append("\n");

        // Location
        if (finding.endpoint() != null && finding.endpoint().location() != null) {
            sb.append("   ");
            sb.append(colorize("at ", Ansi.Color.WHITE, false));
            sb.append(finding.endpoint().location().toString());
            sb.append("\n");
        }

        // Recommendation
        if (finding.recommendation() != null) {
            sb.append("   ");
            sb.append(colorize("Recommendation: ", Ansi.Color.GREEN, false));
            sb.append(finding.recommendation());
            sb.append("\n");
        }

        return sb.toString();
    }

    private String formatFooter(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");

        if (result.getTotalFindings() == 0) {
            sb.append(colorize("No security issues found.", Ansi.Color.GREEN, true));
        } else {
            int critical = result.getSeverityCounts().getOrDefault(Severity.CRITICAL, 0);
            int high = result.getSeverityCounts().getOrDefault(Severity.HIGH, 0);

            if (critical > 0 || high > 0) {
                sb.append(colorize("Action required: ", Ansi.Color.RED, true));
                sb.append("Found ").append(critical + high).append(" critical/high severity issues.");
            } else {
                sb.append(colorize("Review recommended: ", Ansi.Color.YELLOW, true));
                sb.append("Found ").append(result.getTotalFindings()).append(" potential issues.");
            }
        }

        sb.append("\n");
        return sb.toString();
    }

    private String formatSeverity(Severity severity) {
        String icon = noIcons ? "" : SEVERITY_ICONS.getOrDefault(severity, "") + " ";
        String name = severity.name();

        if (noColor) {
            return icon + name;
        }

        Ansi.Color color = switch (severity) {
            case CRITICAL -> Ansi.Color.RED;
            case HIGH -> Ansi.Color.RED;
            case MEDIUM -> Ansi.Color.YELLOW;
            case LOW -> Ansi.Color.CYAN;
            case INFO -> Ansi.Color.WHITE;
        };

        return ansi().fg(color).bold().a(icon + name).reset().toString();
    }

    private String formatClassification(SecurityClassification classification) {
        String icon = noIcons ? "" : CLASSIFICATION_ICONS.getOrDefault(classification, "") + " ";
        String name = classification.name().replace("_", " ");

        if (noColor) {
            return icon + name;
        }

        Ansi.Color color = switch (classification) {
            case PUBLIC -> Ansi.Color.RED;
            case AUTHENTICATED -> Ansi.Color.YELLOW;
            case ROLE_RESTRICTED -> Ansi.Color.GREEN;
            case POLICY_RESTRICTED -> Ansi.Color.CYAN;
        };

        return ansi().fg(color).bold().a(icon + name).reset().toString();
    }

    private String formatMethods(java.util.Set<HttpMethod> methods) {
        String methodStr = methods.stream()
                .map(Enum::name)
                .sorted()
                .reduce((a, b) -> a + "," + b)
                .orElse("ALL");

        if (noColor) {
            return "[" + methodStr + "]";
        }

        // Color based on whether it includes write methods
        boolean hasWrite = methods.stream().anyMatch(HttpMethod::isWriteMethod);
        Ansi.Color color = hasWrite ? Ansi.Color.YELLOW : Ansi.Color.CYAN;

        return ansi().fg(color).a("[" + methodStr + "]").reset().toString();
    }

    private String colorize(String text, Ansi.Color color, boolean bold) {
        if (noColor) {
            return text;
        }

        Ansi ansi = ansi().fg(color);
        if (bold) {
            ansi = ansi.bold();
        }
        return ansi.a(text).reset().toString();
    }

    private String formatDuration(long millis) {
        if (millis < 1000) {
            return millis + "ms";
        }
        return String.format("%.2fs", millis / 1000.0);
    }
}
