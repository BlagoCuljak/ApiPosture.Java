package com.apiposture.rules.exposure;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP001: Detects public endpoints without explicit @PermitAll annotation.
 * These endpoints may be unintentionally exposed.
 */
public class PublicWithoutExplicitIntentRule implements SecurityRule {

    @Override
    public String getId() {
        return "AP001";
    }

    @Override
    public String getName() {
        return "Public without explicit intent";
    }

    @Override
    public String getDescription() {
        return "Detects public endpoints that lack explicit @PermitAll annotation, " +
                "which may indicate unintentional exposure.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.HIGH;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        // Only check public endpoints
        if (endpoint.classification() != SecurityClassification.PUBLIC) {
            return Optional.empty();
        }

        AuthorizationInfo auth = endpoint.authorization();

        // If explicitly marked with @PermitAll, it's intentional
        if (auth != null && auth.hasPermitAll()) {
            return Optional.empty();
        }

        // Public endpoint without explicit @PermitAll
        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Endpoint '%s' is publicly accessible without explicit @PermitAll annotation"
                        .formatted(endpoint.route()))
                .endpoint(endpoint)
                .recommendation("Add @PermitAll to explicitly indicate public access, or add appropriate security annotations")
                .build());
    }
}
