package com.apiposture.cli.commands;

import com.apiposture.cli.output.JsonFormatter;
import com.apiposture.cli.output.MarkdownFormatter;
import com.apiposture.cli.output.OutputFormatter;
import com.apiposture.cli.output.TerminalFormatter;
import com.apiposture.core.analysis.ProjectAnalyzer;
import com.apiposture.core.models.ScanResult;
import com.apiposture.core.models.SecurityClassification;
import com.apiposture.core.models.Severity;
import com.apiposture.rules.RuleEngine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Scan command for analyzing a Spring Boot project.
 */
@Command(
        name = "scan",
        description = "Scan a Spring Boot project for security issues",
        mixinStandardHelpOptions = true
)
public class ScanCommand implements Callable<Integer> {

    @ParentCommand
    private com.apiposture.cli.ApiPosture parent;

    @Parameters(index = "0", description = "Path to the project to scan", defaultValue = ".")
    private Path projectPath;

    @Option(names = {"-o", "--output"}, description = "Output format: terminal, json, markdown (default: terminal)")
    private OutputFormat output = OutputFormat.terminal;

    @Option(names = {"-f", "--output-file"}, description = "Write output to file instead of stdout")
    private Path outputFile;

    @Option(names = {"--severity"}, description = "Minimum severity to report: info, low, medium, high, critical")
    private Severity minSeverity = Severity.INFO;

    @Option(names = {"--fail-on"}, description = "Exit with code 1 if findings at or above this severity")
    private Severity failOnSeverity;

    @Option(names = {"--sort-by"}, description = "Sort findings by: severity, route, method, classification")
    private SortBy sortBy = SortBy.severity;

    @Option(names = {"--classification"}, description = "Filter by classifications (comma-separated)")
    private List<SecurityClassification> classifications;

    @Option(names = {"--method"}, description = "Filter by HTTP methods (comma-separated)")
    private List<String> methods;

    @Option(names = {"--exclude"}, description = "Glob patterns to exclude")
    private List<String> excludePatterns;

    @Option(names = {"--disable-rule"}, description = "Disable specific rules by ID (e.g., AP001)")
    private List<String> disabledRules;

    public enum OutputFormat {
        terminal, json, markdown
    }

    public enum SortBy {
        severity, route, method, classification
    }

    @Override
    public Integer call() {
        try {
            // Validate project path
            if (!Files.exists(projectPath)) {
                System.err.println("Error: Project path does not exist: " + projectPath);
                return 1;
            }

            if (!Files.isDirectory(projectPath)) {
                System.err.println("Error: Project path is not a directory: " + projectPath);
                return 1;
            }

            // Create analyzer
            ProjectAnalyzer analyzer = new ProjectAnalyzer(
                    excludePatterns != null ? excludePatterns : List.of()
            );

            // Analyze project
            ProjectAnalyzer.AnalysisResult analysisResult = analyzer.analyze(projectPath);

            // Create rule engine and configure
            RuleEngine ruleEngine = new RuleEngine();
            ruleEngine.setMinimumSeverity(minSeverity);

            if (disabledRules != null) {
                disabledRules.forEach(ruleEngine::disableRule);
            }

            // Run rules
            ScanResult scanResult = ruleEngine.evaluateToScanResult(analysisResult.toScanResult());

            // Filter results if needed
            scanResult = filterResults(scanResult);

            // Format output
            OutputFormatter formatter = createFormatter();
            String formattedOutput = formatter.format(scanResult);

            // Write output
            if (outputFile != null) {
                Files.writeString(outputFile, formattedOutput);
                System.out.println("Output written to: " + outputFile);
            } else {
                System.out.println(formattedOutput);
            }

            // Check fail-on condition
            if (failOnSeverity != null && scanResult.hasFindings(failOnSeverity)) {
                return 1;
            }

            return 0;

        } catch (IOException e) {
            System.err.println("Error scanning project: " + e.getMessage());
            return 1;
        }
    }

    private ScanResult filterResults(ScanResult result) {
        var endpoints = result.endpoints();
        var findings = result.findings();

        // Filter by classification
        if (classifications != null && !classifications.isEmpty()) {
            Set<SecurityClassification> classSet = Set.copyOf(classifications);
            endpoints = endpoints.stream()
                    .filter(e -> e.classification() != null && classSet.contains(e.classification()))
                    .toList();
            findings = findings.stream()
                    .filter(f -> f.endpoint() != null &&
                            f.endpoint().classification() != null &&
                            classSet.contains(f.endpoint().classification()))
                    .toList();
        }

        // Filter by HTTP method
        if (methods != null && !methods.isEmpty()) {
            Set<String> methodSet = methods.stream()
                    .map(String::toUpperCase)
                    .collect(java.util.stream.Collectors.toSet());
            endpoints = endpoints.stream()
                    .filter(e -> e.methods().stream()
                            .anyMatch(m -> methodSet.contains(m.name())))
                    .toList();
            findings = findings.stream()
                    .filter(f -> f.endpoint() != null &&
                            f.endpoint().methods().stream()
                                    .anyMatch(m -> methodSet.contains(m.name())))
                    .toList();
        }

        return ScanResult.builder()
                .projectPath(result.projectPath())
                .endpoints(endpoints)
                .findings(findings)
                .scannedFiles(result.scannedFiles())
                .scanDuration(result.scanDuration())
                .timestamp(result.timestamp())
                .build();
    }

    private OutputFormatter createFormatter() {
        boolean noColor = parent != null && parent.isNoColor();
        boolean noIcons = parent != null && parent.isNoIcons();

        return switch (output) {
            case terminal -> new TerminalFormatter(noColor, noIcons);
            case json -> new JsonFormatter();
            case markdown -> new MarkdownFormatter();
        };
    }
}
