package com.apiposture.cli.output;

import com.apiposture.core.models.*;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * HTML output formatter — produces a self-contained HTML report.
 */
public class HtmlFormatter implements OutputFormatter {

    @Override
    public String format(ScanResult result) {
        StringBuilder sb = new StringBuilder();

        sb.append(htmlHead("ApiPosture Security Scan Report"));
        sb.append("<body><div class=\"container\">\n");
        sb.append("<h1>&#x1F6E1;&#xFE0F; ApiPosture Security Scan Report</h1>\n");
        sb.append("<div class=\"meta\"><strong>Generated:</strong> ")
                .append(ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT))
                .append(" UTC</div>\n");

        renderSummary(sb, result);
        renderSeverityBreakdown(sb, result);

        if (!result.endpoints().isEmpty()) {
            renderEndpoints(sb, result);
        }

        if (!result.findings().isEmpty()) {
            sb.append("<h2>Security Findings</h2>\n");
            for (Finding finding : result.findings()) {
                renderFinding(sb, finding);
            }
        } else {
            sb.append("<h2>Security Findings</h2>\n");
            sb.append("<div class=\"success\">&#x2705; No security findings detected!</div>\n");
        }

        sb.append("</div></body></html>\n");
        return sb.toString();
    }

    private void renderSummary(StringBuilder sb, ScanResult result) {
        sb.append("<h2>Summary</h2>\n");
        sb.append("<div class=\"summary-grid\">\n");
        summaryCard(sb, "Project", result.projectPath());
        summaryCard(sb, "Files Scanned", String.valueOf(result.scannedFiles()));
        summaryCard(sb, "Total Endpoints", String.valueOf(result.getTotalEndpoints()));
        summaryCard(sb, "Total Findings", String.valueOf(result.getTotalFindings()));
        summaryCard(sb, "Scan Duration", formatDuration(result.scanDuration().toMillis()));
        sb.append("</div>\n");
        sb.append("<p class=\"section-subtitle\"><strong>Timestamp:</strong> ")
                .append(escape(DateTimeFormatter.ISO_INSTANT.format(result.timestamp())))
                .append("</p>\n");
    }

    private void renderSeverityBreakdown(StringBuilder sb, ScanResult result) {
        if (result.getTotalFindings() == 0) return;

        sb.append("<h2>Severity Breakdown</h2>\n");
        sb.append("<ul class=\"severity-list\">\n");

        Map<Severity, Integer> counts = result.getSeverityCounts();
        for (Severity severity : new Severity[]{
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
            int count = counts.getOrDefault(severity, 0);
            if (count > 0) {
                String sev = severity.name().toLowerCase();
                sb.append("<li><span class=\"severity-badge severity-").append(escape(sev)).append("\">")
                        .append(escape(severity.name())).append("</span> &mdash; ").append(count)
                        .append(" finding(s)</li>\n");
            }
        }
        sb.append("</ul>\n");
    }

    private void renderEndpoints(StringBuilder sb, ScanResult result) {
        sb.append("<h2>Endpoints</h2>\n");

        Map<SecurityClassification, java.util.List<Endpoint>> byClass = result.getEndpointsByClassification();

        for (SecurityClassification classification : SecurityClassification.values()) {
            java.util.List<Endpoint> endpoints = byClass.get(classification);
            if (endpoints == null || endpoints.isEmpty()) continue;

            sb.append("<h3>").append(escape(classification.name())).append(" (").append(endpoints.size()).append(")</h3>\n");
            sb.append("<table>\n");
            sb.append("  <thead><tr><th>Method</th><th>Route</th><th>Controller</th><th>Location</th></tr></thead>\n");
            sb.append("  <tbody>\n");

            for (Endpoint endpoint : endpoints) {
                sb.append("    <tr>");
                sb.append("<td><code>").append(escape(endpoint.formatMethods())).append("</code></td>");
                sb.append("<td><code>").append(escape(endpoint.route())).append("</code></td>");
                sb.append("<td>").append(escape(endpoint.controllerName())).append(".").append(escape(endpoint.methodName())).append("()</td>");
                sb.append("<td>").append(escape(formatLocation(endpoint.location()))).append("</td>");
                sb.append("</tr>\n");
            }
            sb.append("  </tbody>\n</table>\n");
        }
    }

    private void renderFinding(StringBuilder sb, Finding finding) {
        String sev = finding.severity().name().toLowerCase();
        sb.append("<div class=\"finding ").append(escape(sev)).append("\">\n");
        sb.append("  <span class=\"severity-badge severity-").append(escape(sev)).append("\">")
                .append(escape(finding.severity().name())).append("</span>\n");
        sb.append("  <h3>[").append(escape(finding.ruleId())).append("] ").append(escape(finding.ruleName())).append("</h3>\n");

        if (finding.endpoint() != null) {
            sb.append("  <p><strong>Endpoint:</strong> <code>")
                    .append(escape(finding.endpoint().formatMethods())).append(" ").append(escape(finding.endpoint().route()))
                    .append("</code></p>\n");
            if (finding.endpoint().location() != null) {
                sb.append("  <p><strong>Location:</strong> <code>")
                        .append(escape(formatLocation(finding.endpoint().location()))).append("</code></p>\n");
            }
        }

        sb.append("  <p>").append(escape(finding.message())).append("</p>\n");

        if (finding.recommendation() != null) {
            sb.append("  <div class=\"recommendation\"><div class=\"recommendation-title\">Recommendation</div><div>")
                    .append(escape(finding.recommendation())).append("</div></div>\n");
        }

        sb.append("</div>\n");
    }

    private static void summaryCard(StringBuilder sb, String label, String value) {
        sb.append("<div class=\"summary-card\"><div class=\"label\">").append(escape(label))
                .append("</div><div class=\"value\">").append(escape(value)).append("</div></div>\n");
    }

    private static String formatLocation(SourceLocation location) {
        if (location == null) return "unknown";
        return location.filePath() + ":" + location.lineNumber();
    }

    private static String formatDuration(long millis) {
        if (millis < 1000) return millis + "ms";
        return String.format("%.2fs", millis / 1000.0);
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static String htmlHead(String title) {
        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "    <title>" + escape(title) + "</title>\n" +
                "    <style>\n" +
                "        :root{--panel:#fff;--border:#dbe3ee;--text:#1e293b;--muted:#64748b;--critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#2563eb;--shadow:rgba(15,23,42,0.08);}\n" +
                "        *{box-sizing:border-box;}html{scroll-behavior:smooth;}\n" +
                "        body{margin:0;padding:32px;background:linear-gradient(to bottom right,#f8fafc,#eef4fb);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.6;}\n" +
                "        .container{max-width:1500px;margin:0 auto;}\n" +
                "        h1{font-size:42px;margin-bottom:8px;color:#0f172a;}h2{margin-top:50px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:12px;color:#0f172a;}h3{margin-top:0;color:#1e293b;}\n" +
                "        .meta{color:var(--muted);margin-bottom:40px;}\n" +
                "        .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin-bottom:40px;}\n" +
                "        .summary-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:24px;transition:0.2s ease;box-shadow:0 6px 20px var(--shadow);}\n" +
                "        .summary-card:hover{transform:translateY(-2px);}.summary-card .label{color:var(--muted);font-size:14px;}.summary-card .value{font-size:34px;font-weight:700;margin-top:8px;color:#0f172a;}\n" +
                "        table{width:100%;border-collapse:collapse;margin-top:18px;margin-bottom:30px;border-radius:14px;box-shadow:0 6px 18px var(--shadow);}\n" +
                "        th{background:#eff6ff;color:#1e293b;text-align:left;padding:15px;font-size:14px;border-bottom:1px solid var(--border);}\n" +
                "        td{background:var(--panel);border-top:1px solid var(--border);padding:15px;vertical-align:top;}tr:hover td{background:#f8fbff;}\n" +
                "        code{background:#eef2ff;color:#1d4ed8;padding:4px 8px;border-radius:6px;font-family:Consolas,monospace;font-size:13px;}\n" +
                "        .finding{background:var(--panel);border:1px solid var(--border);border-left:6px solid var(--medium);border-radius:16px;padding:24px;margin-bottom:24px;transition:0.2s ease;box-shadow:0 6px 18px var(--shadow);}\n" +
                "        .finding:hover{transform:translateY(-2px);}.finding.critical{border-left-color:var(--critical);}.finding.high{border-left-color:var(--high);}.finding.medium{border-left-color:var(--medium);}.finding.low{border-left-color:var(--low);}\n" +
                "        .severity-badge{display:inline-block;padding:5px 12px;border-radius:999px;font-size:12px;font-weight:bold;text-transform:uppercase;margin-bottom:14px;}\n" +
                "        .severity-critical{background:#fee2e2;color:#b91c1c;}.severity-high{background:#ffedd5;color:#c2410c;}.severity-medium{background:#fef3c7;color:#b45309;}.severity-low{background:#dbeafe;color:#1d4ed8;}.severity-info{background:#e5e7eb;color:#4b5563;}\n" +
                "        .recommendation{margin-top:20px;background:#f8fafc;border:1px solid var(--border);border-radius:12px;padding:18px;}.recommendation-title{color:#2563eb;font-weight:bold;margin-bottom:10px;}\n" +
                "        .severity-list{padding-left:18px;}.severity-list li{margin-bottom:8px;}\n" +
                "        .success{padding:18px;border-radius:12px;background:#dcfce7;color:#166534;border:1px solid #86efac;font-weight:bold;}\n" +
                "        .section-subtitle{color:var(--muted);margin-bottom:20px;}\n" +
                "    </style>\n</head>\n";
    }
}
