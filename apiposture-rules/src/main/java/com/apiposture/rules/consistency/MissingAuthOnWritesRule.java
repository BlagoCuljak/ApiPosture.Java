package com.apiposture.rules.consistency;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP004: Detects write operations (POST, PUT, DELETE, PATCH) without any authorization.
 * This is a critical security risk.
 */
public class MissingAuthOnWritesRule implements SecurityRule {

    @Override
    public String getId() {
        return "AP004";
    }

    @Override
    public String getName() {
        return "Missing authorization on write operation";
    }

    @Override
    public String getDescription() {
        return "Detects write operations (POST, PUT, DELETE, PATCH) that have no authorization, " +
                "which is a critical security vulnerability.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.CRITICAL;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        // Check if it has write methods
        if (!endpoint.hasWriteMethods()) {
            return Optional.empty();
        }

        // Check if endpoint is public (no authorization)
        if (endpoint.classification() != SecurityClassification.PUBLIC) {
            return Optional.empty();
        }

        AuthorizationInfo auth = endpoint.authorization();

        // If explicitly marked with @PermitAll, AP002 handles that
        if (auth != null && auth.hasPermitAll()) {
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
                .message("Endpoint '%s' allows unauthenticated write operations: %s"
                        .formatted(endpoint.route(), writeMethods))
                .endpoint(endpoint)
                .recommendation("Add @PreAuthorize, @Secured, or @RolesAllowed to restrict write access")
                .build());
    }
}
