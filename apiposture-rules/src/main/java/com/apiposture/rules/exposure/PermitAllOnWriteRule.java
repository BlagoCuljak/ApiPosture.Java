package com.apiposture.rules.exposure;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP002: Detects @PermitAll on write operations (POST, PUT, DELETE, PATCH).
 * Public write endpoints are a security risk.
 */
public class PermitAllOnWriteRule implements SecurityRule {

    @Override
    public String getId() {
        return "AP002";
    }

    @Override
    public String getName() {
        return "PermitAll on write operation";
    }

    @Override
    public String getDescription() {
        return "Detects endpoints with @PermitAll on write operations (POST, PUT, DELETE, PATCH), " +
                "which may allow unauthorized data modification.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.HIGH;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        // Check if it has write methods
        if (!endpoint.hasWriteMethods()) {
            return Optional.empty();
        }

        AuthorizationInfo auth = endpoint.authorization();

        // Only trigger if explicitly marked with @PermitAll
        if (auth == null || !auth.hasPermitAll()) {
            return Optional.empty();
        }

        String writeMethods = endpoint.methods().stream()
                .filter(HttpMethod::isWriteMethod)
                .map(Enum::name)
                .reduce((a, b) -> a + ", " + b)
                .orElse("");

        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Endpoint '%s' allows public access (%s) on write operations: %s"
                        .formatted(endpoint.route(), "@PermitAll", writeMethods))
                .endpoint(endpoint)
                .recommendation("Remove @PermitAll and add appropriate authorization for write operations")
                .build());
    }
}
