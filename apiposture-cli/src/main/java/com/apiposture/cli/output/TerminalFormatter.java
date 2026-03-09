package com.apiposture.cli.output;

import com.apiposture.core.models.*;
import org.fusesource.jansi.Ansi;

import java.util.*;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Terminal output formatter with ANSI colors.
 *
 * Output ordering (printed top → bottom, so scrolling up reveals older output):
 *   1. Critical details   (top of scrollback — reached by scrolling all the way up)
 *   2. High details
 *   3. Medium details
 *   4. Low compact grid   (first thing seen when scrolling up past the separator)
 *   5. Scroll-hint separator
 *   6. Scan summary table
 *   7. Severity overview chart
 *   8. Endpoints table    (bottom — visible immediately after scan completes)
 */
public class TerminalFormatter implements OutputFormatter {

    private static final int RULE_WIDTH        = 60;
    private static final int COMPACT_COL_WIDTH = 40;

    private final boolean noColor;
    private final boolean noIcons;
    private final AccessibilityHelper accessibility;

    public TerminalFormatter(boolean noColor, boolean noIcons) {
        this.accessibility = AccessibilityHelper.create(noColor, noIcons);
        this.noColor = !accessibility.isUseColors();
        this.noIcons = !accessibility.isUseIcons();
    }

    @Override
    public String format(ScanResult result) {
        StringBuilder sb = new StringBuilder();

        // 1. Header
        sb.append(formatHeader());
        sb.append("\n");

        // 2. Findings section (Critical/High/Medium panels, then Low/Info compact grid)
        if (!result.findings().isEmpty()) {
            sb.append(formatFindingsSection(result));
        }

        // 3. Scroll-hint separator
        if (!result.findings().isEmpty()) {
            sb.append(formatScrollHint());
        }

        // 4. Summary stats
        sb.append(formatSummary(result));

        // 5. Severity overview chart
        if (!result.findings().isEmpty()) {
            sb.append(formatSeverityChart(result));
            sb.append("\n");
        }

        // 6. Endpoints table (visible immediately — printed last)
        if (!result.endpoints().isEmpty()) {
            sb.append(formatEndpointsSection(result));
            sb.append("\n");
        }

        // 7. Final status line
        sb.append(formatFooter(result));

        return sb.toString();
    }

    // -- Header ------------------------------------------------------------------

    private String formatHeader() {
        String title = "ApiPosture Security Scan";
        if (noColor) {
            return rule(title) + "\n";
        }
        return ansi().bold().fgCyan().a(rule(title)).reset().a("\n").toString() + "\n";
    }

    // -- Findings section --------------------------------------------------------

    private String formatFindingsSection(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        Map<Severity, List<Finding>> bySeverity = result.getFindingsBySeverity();

        // Compact grid — Info then Low (top of scrollback, requires most scrolling to reach)
        for (Severity severity : new Severity[]{Severity.INFO, Severity.LOW}) {
            List<Finding> group = bySeverity.getOrDefault(severity, List.of());
            if (!group.isEmpty()) {
                sb.append(formatCompactGroup(severity, group));
            }
        }

        // Detailed panels — Medium then High then Critical last
        // (Critical is just above the scroll-hint separator = first seen when scrolling up)
        for (Severity severity : new Severity[]{Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}) {
            List<Finding> group = bySeverity.getOrDefault(severity, List.of());
            if (!group.isEmpty()) {
                sb.append(formatDetailedGroup(severity, group));
            }
        }

        return sb.toString();
    }

    private String formatDetailedGroup(Severity severity, List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        String indicator = accessibility.getSeverityIndicator(severity);
        sb.append(sectionRule(indicator + " " + severity.name() + " Findings (" + findings.size() + ")"));
        for (Finding finding : findings) {
            sb.append(formatFindingDetail(finding));
            sb.append("\n");
        }
        return sb.toString();
    }

    private String formatCompactGroup(Severity severity, List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        String indicator = accessibility.getSeverityIndicator(severity);
        sb.append(sectionRule(indicator + " " + severity.name() + " Findings (" + findings.size() + ")"));

        // Column header
        String hdr = String.format("  %-10s %-" + COMPACT_COL_WIDTH + "s %s", "Rule", "Endpoint", "Message");
        sb.append(noColor ? hdr : colorize(hdr, Ansi.Color.WHITE, true)).append("\n");

        for (Finding finding : findings) {
            sb.append(formatCompactFinding(finding));
        }
        sb.append("\n");
        return sb.toString();
    }

    private String formatFindingDetail(Finding finding) {
        StringBuilder sb = new StringBuilder();
        sb.append(colorize("  " + accessibility.getSeverityIndicator(finding.severity())
                + " [" + finding.ruleId() + "] " + finding.ruleName()
                + " (" + finding.severity().name() + ")",
                severityColor(finding.severity()), true)).append("\n");

        if (finding.endpoint() != null) {
            sb.append("  ").append(colorize("Route: ", Ansi.Color.WHITE, true))
              .append(finding.endpoint().route()).append("\n");
            if (finding.endpoint().location() != null) {
                sb.append("  ").append(colorize("Location: ", Ansi.Color.WHITE, true))
                  .append(finding.endpoint().location()).append("\n");
            }
        }

        sb.append("\n  ").append(finding.message()).append("\n");

        if (finding.recommendation() != null) {
            sb.append("\n  ").append(colorize("Recommendation: ", Ansi.Color.GREEN, false))
              .append(finding.recommendation()).append("\n");
        }
        return sb.toString();
    }

    private String formatCompactFinding(Finding finding) {
        String ruleId = String.format("%-10s", "[" + finding.ruleId() + "]");
        String endpoint = "";
        if (finding.endpoint() != null) {
            String ep = finding.endpoint().formatMethods() + " " + finding.endpoint().route();
            endpoint = ep.length() <= COMPACT_COL_WIDTH
                    ? ep : ep.substring(0, COMPACT_COL_WIDTH - 3) + "...";
        }
        String endpointPadded = String.format("%-" + COMPACT_COL_WIDTH + "s", endpoint);
        String message = finding.message() != null && finding.message().length() > 55
                ? finding.message().substring(0, 52) + "..."
                : finding.message();

        if (noColor) {
            return "  " + ruleId + " " + endpointPadded + " " + message + "\n";
        }
        return "  " + colorize(ruleId, Ansi.Color.YELLOW, false)
                + " " + colorize(endpointPadded, Ansi.Color.WHITE, false)
                + " " + message + "\n";
    }

    // -- Scroll-hint separator ----------------------------------------------------

    private String formatScrollHint() {
        String hint = "^^^^ Scroll up for finding details ^^^^";
        if (noColor) {
            return "\n" + rule(hint) + "\n\n";
        }
        return "\n" + ansi().fgBlack().bold().a(rule(hint)).reset().a("\n").toString() + "\n";
    }

    // -- Summary ------------------------------------------------------------------

    private String formatSummary(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(sectionRule("Scan Summary"));
        sb.append(metricRow("Project",        result.projectPath()));
        sb.append(metricRow("Files scanned",  String.valueOf(result.scannedFiles())));
        sb.append(metricRow("Endpoints",      String.valueOf(result.getTotalEndpoints())));
        sb.append(metricRow("Findings",       String.valueOf(result.getTotalFindings())));
        sb.append(metricRow("Duration",       formatDuration(result.scanDuration().toMillis())));
        sb.append("\n");
        return sb.toString();
    }

    private String metricRow(String label, String value) {
        String lbl = String.format("%-20s", label);
        return "  " + (noColor ? lbl : colorize(lbl, Ansi.Color.WHITE, true)) + " " + value + "\n";
    }

    // -- Severity chart -----------------------------------------------------------

    private String formatSeverityChart(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(sectionRule("Severity Overview"));

        Map<Severity, Integer> counts = result.getSeverityCounts();
        int max = counts.values().stream().max(Integer::compareTo).orElse(1);

        for (Severity severity : new Severity[]{
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
            int count = counts.getOrDefault(severity, 0);
            if (count == 0) continue;

            String indicator = accessibility.getSeverityIndicator(severity);
            String label     = String.format("%-8s", severity.name());
            int barLen       = Math.max(1, (count * 20) / max);
            String bar       = "#".repeat(barLen);

            if (noColor) {
                sb.append("  ").append(indicator).append(" ").append(label)
                  .append(" ").append(bar).append(" ").append(count).append("\n");
            } else {
                Ansi.Color color = severityColor(severity);
                sb.append("  ").append(indicator).append(" ")
                  .append(colorize(label, color, true)).append(" ")
                  .append(ansi().fg(color).a(bar).reset()).append(" ")
                  .append(colorize(String.valueOf(count), color, true)).append("\n");
            }
        }
        return sb.toString();
    }

    // -- Endpoints table ----------------------------------------------------------

    private String formatEndpointsSection(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(sectionRule("Discovered Endpoints (" + result.getTotalEndpoints() + ")"));

        String hdr = String.format("  %-12s %-38s %-24s %s",
                "Methods", "Route", "Controller", "Classification");
        sb.append(noColor ? hdr : colorize(hdr, Ansi.Color.WHITE, true)).append("\n");
        sb.append(noColor ? "  " + "-".repeat(96) : colorize("  " + "-".repeat(96), Ansi.Color.WHITE, false))
          .append("\n");

        Map<SecurityClassification, List<Endpoint>> byClass = result.getEndpointsByClassification();
        for (SecurityClassification cls : SecurityClassification.values()) {
            List<Endpoint> endpoints = byClass.getOrDefault(cls, List.of());
            for (Endpoint endpoint : endpoints) {
                sb.append(formatEndpointRow(endpoint));
            }
        }
        return sb.toString();
    }

    private String formatEndpointRow(Endpoint endpoint) {
        boolean hasWrite = endpoint.methods().stream().anyMatch(HttpMethod::isWriteMethod);
        Ansi.Color methodColor = hasWrite ? Ansi.Color.YELLOW : Ansi.Color.CYAN;

        String methods    = String.format("%-12s", endpoint.formatMethods());
        String route      = endpoint.route();
        String controller = endpoint.controllerName() + "." + endpoint.methodName() + "()";
        String routePad   = String.format("%-38s", route.length() > 37 ? route.substring(0, 34) + "..." : route);
        String ctrlPad    = String.format("%-24s", controller.length() > 23 ? controller.substring(0, 20) + "..." : controller);

        if (noColor) {
            return "  " + methods + " " + routePad + " " + ctrlPad + " "
                    + accessibility.getClassificationIndicator(endpoint.classification())
                    + " " + endpoint.classification().name().replace("_", " ") + "\n";
        }

        return "  " + colorize(methods, methodColor, false)
                + " " + routePad
                + " " + colorize(ctrlPad, Ansi.Color.WHITE, false)
                + " " + formatClassification(endpoint.classification()) + "\n";
    }

    // -- Footer -------------------------------------------------------------------

    private String formatFooter(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");
        if (result.getTotalFindings() == 0) {
            sb.append(colorize(accessibility.getSuccessIndicator() + " No security findings!",
                    Ansi.Color.GREEN, true));
        } else {
            int critical = result.getSeverityCounts().getOrDefault(Severity.CRITICAL, 0);
            int high     = result.getSeverityCounts().getOrDefault(Severity.HIGH, 0);
            if (critical > 0 || high > 0) {
                sb.append(colorize(accessibility.getFailureIndicator() + " Action required: ",
                        Ansi.Color.RED, true));
                sb.append("Found ").append(critical + high).append(" critical/high severity issues.");
            } else {
                sb.append(colorize(accessibility.getWarningIndicator() + " Review recommended: ",
                        Ansi.Color.YELLOW, true));
                sb.append("Found ").append(result.getTotalFindings()).append(" potential issues.");
            }
        }
        sb.append("\n");
        return sb.toString();
    }

    // -- Helpers ------------------------------------------------------------------

    private String formatClassification(SecurityClassification classification) {
        String indicator = accessibility.getClassificationIndicator(classification);
        String name = classification.name().replace("_", " ");
        Ansi.Color color = switch (classification) {
            case PUBLIC -> Ansi.Color.RED;
            case AUTHENTICATED -> Ansi.Color.YELLOW;
            case ROLE_RESTRICTED -> Ansi.Color.GREEN;
            case POLICY_RESTRICTED -> Ansi.Color.CYAN;
        };
        return noColor ? indicator + " " + name
                : ansi().fg(color).bold().a(indicator + " " + name).reset().toString();
    }

    private Ansi.Color severityColor(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> Ansi.Color.RED;
            case MEDIUM -> Ansi.Color.YELLOW;
            case LOW -> Ansi.Color.CYAN;
            case INFO -> Ansi.Color.WHITE;
        };
    }

    private String colorize(String text, Ansi.Color color, boolean bold) {
        if (noColor) return text;
        Ansi a = ansi().fg(color);
        if (bold) a = a.bold();
        return a.a(text).reset().toString();
    }

    /** Full-width rule line with optional centred title. */
    private String rule(String title) {
        int pad = Math.max(0, RULE_WIDTH - title.length() - 4);
        return "-- " + title + " " + "-".repeat(pad);
    }

    /** Section rule with newline prepended. */
    private String sectionRule(String title) {
        String r = rule(title);
        return noColor ? "\n" + r + "\n"
                : "\n" + ansi().bold().fgCyan().a(r).reset().a("\n").toString();
    }

    private String formatDuration(long millis) {
        return millis < 1000 ? millis + "ms" : String.format("%.2fs", millis / 1000.0);
    }
}
