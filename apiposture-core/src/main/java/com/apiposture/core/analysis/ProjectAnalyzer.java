package com.apiposture.core.analysis;

import com.apiposture.core.authorization.AnnotationAuthorizationExtractor;
import com.apiposture.core.classification.SecurityClassifier;
import com.apiposture.core.discovery.ControllerEndpointDiscoverer;
import com.apiposture.core.discovery.EndpointDiscoverer;
import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.ScanResult;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Main analyzer that orchestrates endpoint discovery and classification.
 */
public class ProjectAnalyzer {

    private final SourceFileLoader fileLoader;
    private final List<EndpointDiscoverer> discoverers;
    private final SecurityClassifier classifier;

    public ProjectAnalyzer() {
        this(List.of());
    }

    public ProjectAnalyzer(List<String> excludePatterns) {
        this.fileLoader = new SourceFileLoader(excludePatterns);
        this.classifier = new SecurityClassifier();

        AnnotationAuthorizationExtractor authExtractor = new AnnotationAuthorizationExtractor();
        this.discoverers = List.of(
                new ControllerEndpointDiscoverer(authExtractor)
        );
    }

    /**
     * Analyze a project and return discovered endpoints.
     */
    public AnalysisResult analyze(Path projectPath) throws IOException {
        Instant start = Instant.now();

        List<SourceFileLoader.ParsedFile> parsedFiles = fileLoader.loadProject(projectPath);
        List<Endpoint> allEndpoints = new ArrayList<>();

        for (SourceFileLoader.ParsedFile file : parsedFiles) {
            for (EndpointDiscoverer discoverer : discoverers) {
                List<Endpoint> endpoints = discoverer.discover(file.compilationUnit(), file.getAbsolutePath());
                // Classify each endpoint
                List<Endpoint> classified = endpoints.stream()
                        .map(classifier::classify)
                        .toList();
                allEndpoints.addAll(classified);
            }
        }

        Duration duration = Duration.between(start, Instant.now());

        return new AnalysisResult(
                projectPath.toAbsolutePath().toString(),
                allEndpoints,
                parsedFiles.size(),
                duration
        );
    }

    /**
     * Result of project analysis.
     */
    public record AnalysisResult(
            String projectPath,
            List<Endpoint> endpoints,
            int scannedFiles,
            Duration duration
    ) {
        /**
         * Convert to ScanResult (without findings - those are added by RuleEngine).
         */
        public ScanResult toScanResult() {
            return ScanResult.builder()
                    .projectPath(projectPath)
                    .endpoints(endpoints)
                    .findings(List.of())
                    .scannedFiles(scannedFiles)
                    .scanDuration(duration)
                    .build();
        }
    }
}
