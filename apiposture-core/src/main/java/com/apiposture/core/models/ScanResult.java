package com.apiposture.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Result of a security scan containing endpoints, findings, and metadata.
 */
public record ScanResult(
        @JsonProperty("projectPath") String projectPath,
        @JsonProperty("endpoints") List<Endpoint> endpoints,
        @JsonProperty("findings") List<Finding> findings,
        @JsonProperty("scannedFiles") int scannedFiles,
        @JsonProperty("scanDuration") Duration scanDuration,
        @JsonProperty("timestamp") Instant timestamp
) {
    /**
     * Create scan result with current timestamp.
     */
    public ScanResult(String projectPath, List<Endpoint> endpoints, List<Finding> findings,
                      int scannedFiles, Duration scanDuration) {
        this(projectPath, endpoints, findings, scannedFiles, scanDuration, Instant.now());
    }

    /**
     * Get findings grouped by severity.
     */
    public Map<Severity, List<Finding>> getFindingsBySeverity() {
        Map<Severity, List<Finding>> result = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            result.put(severity, new ArrayList<>());
        }
        for (Finding finding : findings) {
            result.get(finding.severity()).add(finding);
        }
        return result;
    }

    /**
     * Get count of findings for each severity.
     */
    public Map<Severity, Integer> getSeverityCounts() {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0);
        }
        for (Finding finding : findings) {
            counts.merge(finding.severity(), 1, Integer::sum);
        }
        return counts;
    }

    /**
     * Get endpoints grouped by classification.
     */
    public Map<SecurityClassification, List<Endpoint>> getEndpointsByClassification() {
        Map<SecurityClassification, List<Endpoint>> result = new EnumMap<>(SecurityClassification.class);
        for (SecurityClassification classification : SecurityClassification.values()) {
            result.put(classification, new ArrayList<>());
        }
        for (Endpoint endpoint : endpoints) {
            if (endpoint.classification() != null) {
                result.get(endpoint.classification()).add(endpoint);
            }
        }
        return result;
    }

    /**
     * Check if there are any findings at or above the given severity.
     */
    public boolean hasFindings(Severity minSeverity) {
        return findings.stream()
                .anyMatch(f -> f.severity().isAtLeast(minSeverity));
    }

    /**
     * Get the highest severity among all findings.
     */
    public Optional<Severity> getHighestSeverity() {
        return findings.stream()
                .map(Finding::severity)
                .max(Comparator.comparingInt(Severity::getLevel));
    }

    /**
     * Get total number of findings.
     */
    public int getTotalFindings() {
        return findings.size();
    }

    /**
     * Get total number of endpoints.
     */
    public int getTotalEndpoints() {
        return endpoints.size();
    }

    /**
     * Builder for ScanResult.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String projectPath;
        private List<Endpoint> endpoints = new ArrayList<>();
        private List<Finding> findings = new ArrayList<>();
        private int scannedFiles;
        private Duration scanDuration;
        private Instant timestamp = Instant.now();

        public Builder projectPath(String projectPath) {
            this.projectPath = projectPath;
            return this;
        }

        public Builder endpoints(List<Endpoint> endpoints) {
            this.endpoints = new ArrayList<>(endpoints);
            return this;
        }

        public Builder addEndpoint(Endpoint endpoint) {
            this.endpoints.add(endpoint);
            return this;
        }

        public Builder findings(List<Finding> findings) {
            this.findings = new ArrayList<>(findings);
            return this;
        }

        public Builder addFinding(Finding finding) {
            this.findings.add(finding);
            return this;
        }

        public Builder scannedFiles(int scannedFiles) {
            this.scannedFiles = scannedFiles;
            return this;
        }

        public Builder scanDuration(Duration scanDuration) {
            this.scanDuration = scanDuration;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ScanResult build() {
            return new ScanResult(projectPath, endpoints, findings, scannedFiles, scanDuration, timestamp);
        }
    }
}
