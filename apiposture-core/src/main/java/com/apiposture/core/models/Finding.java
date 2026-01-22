package com.apiposture.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a security finding from rule analysis.
 */
public record Finding(
        @JsonProperty("ruleId") String ruleId,
        @JsonProperty("ruleName") String ruleName,
        @JsonProperty("severity") Severity severity,
        @JsonProperty("message") String message,
        @JsonProperty("endpoint") Endpoint endpoint,
        @JsonProperty("recommendation") String recommendation
) {
    /**
     * Get the location string for this finding.
     */
    public String getLocationString() {
        if (endpoint == null || endpoint.location() == null) {
            return "unknown";
        }
        return endpoint.location().toString();
    }

    /**
     * Get formatted finding identifier.
     */
    public String getIdentifier() {
        return "[%s] %s".formatted(ruleId, ruleName);
    }

    /**
     * Builder for creating Finding instances.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String ruleId;
        private String ruleName;
        private Severity severity = Severity.INFO;
        private String message;
        private Endpoint endpoint;
        private String recommendation;

        public Builder ruleId(String ruleId) {
            this.ruleId = ruleId;
            return this;
        }

        public Builder ruleName(String ruleName) {
            this.ruleName = ruleName;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder endpoint(Endpoint endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder recommendation(String recommendation) {
            this.recommendation = recommendation;
            return this;
        }

        public Finding build() {
            return new Finding(ruleId, ruleName, severity, message, endpoint, recommendation);
        }
    }
}
