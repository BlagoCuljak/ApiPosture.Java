package com.apiposture.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Represents a discovered API endpoint.
 */
public record Endpoint(
        @JsonProperty("route") String route,
        @JsonProperty("methods") Set<HttpMethod> methods,
        @JsonProperty("type") EndpointType type,
        @JsonProperty("controllerName") String controllerName,
        @JsonProperty("methodName") String methodName,
        @JsonProperty("location") SourceLocation location,
        @JsonProperty("authorization") AuthorizationInfo authorization,
        @JsonProperty("classification") SecurityClassification classification
) {
    /**
     * Create endpoint with default classification (will be computed later).
     */
    public Endpoint(String route, Set<HttpMethod> methods, EndpointType type,
                    String controllerName, String methodName, SourceLocation location,
                    AuthorizationInfo authorization) {
        this(route, methods, type, controllerName, methodName, location, authorization, null);
    }

    /**
     * Check if this endpoint accepts any write methods.
     */
    public boolean hasWriteMethods() {
        return methods.stream().anyMatch(HttpMethod::isWriteMethod);
    }

    /**
     * Check if this endpoint accepts any read methods.
     */
    public boolean hasReadMethods() {
        return methods.stream().anyMatch(HttpMethod::isReadMethod);
    }

    /**
     * Check if this endpoint is public (no authorization required).
     */
    public boolean isPublic() {
        return classification == SecurityClassification.PUBLIC;
    }

    /**
     * Get the fully qualified endpoint identifier.
     */
    public String getIdentifier() {
        return "%s %s".formatted(formatMethods(), route);
    }

    /**
     * Format methods as comma-separated string.
     */
    public String formatMethods() {
        if (methods.isEmpty()) {
            return "ALL";
        }
        return methods.stream()
                .map(Enum::name)
                .sorted()
                .reduce((a, b) -> a + "," + b)
                .orElse("ALL");
    }

    /**
     * Create new endpoint with updated classification.
     */
    public Endpoint withClassification(SecurityClassification newClassification) {
        return new Endpoint(route, methods, type, controllerName, methodName,
                location, authorization, newClassification);
    }

    /**
     * Create new endpoint with updated authorization.
     */
    public Endpoint withAuthorization(AuthorizationInfo newAuthorization) {
        return new Endpoint(route, methods, type, controllerName, methodName,
                location, newAuthorization, classification);
    }

    /**
     * Builder for creating Endpoint instances.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String route;
        private Set<HttpMethod> methods = EnumSet.noneOf(HttpMethod.class);
        private EndpointType type = EndpointType.CONTROLLER;
        private String controllerName;
        private String methodName;
        private SourceLocation location;
        private AuthorizationInfo authorization = AuthorizationInfo.empty();
        private SecurityClassification classification;

        public Builder route(String route) {
            this.route = route;
            return this;
        }

        public Builder methods(Set<HttpMethod> methods) {
            this.methods = EnumSet.copyOf(methods);
            return this;
        }

        public Builder method(HttpMethod method) {
            this.methods.add(method);
            return this;
        }

        public Builder type(EndpointType type) {
            this.type = type;
            return this;
        }

        public Builder controllerName(String controllerName) {
            this.controllerName = controllerName;
            return this;
        }

        public Builder methodName(String methodName) {
            this.methodName = methodName;
            return this;
        }

        public Builder location(SourceLocation location) {
            this.location = location;
            return this;
        }

        public Builder authorization(AuthorizationInfo authorization) {
            this.authorization = Objects.requireNonNullElse(authorization, AuthorizationInfo.empty());
            return this;
        }

        public Builder classification(SecurityClassification classification) {
            this.classification = classification;
            return this;
        }

        public Endpoint build() {
            return new Endpoint(route, methods, type, controllerName, methodName,
                    location, authorization, classification);
        }
    }
}
