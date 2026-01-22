package com.apiposture.rules.surface;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP008: Detects controller endpoints without any security annotations.
 * All endpoints should have explicit security configuration.
 */
public class ControllerWithoutAuthRule implements SecurityRule {

    @Override
    public String getId() {
        return "AP008";
    }

    @Override
    public String getName() {
        return "Controller without security annotation";
    }

    @Override
    public String getDescription() {
        return "Detects controller endpoints that have no security annotations at all, " +
                "which may indicate missing security configuration.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.HIGH;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        // Only check controller endpoints
        if (endpoint.type() != EndpointType.CONTROLLER) {
            return Optional.empty();
        }

        AuthorizationInfo auth = endpoint.authorization();

        // Check if there's ANY security annotation
        if (auth != null && (auth.hasAnySecurity() || auth.hasPermitAll() || auth.hasDenyAll())) {
            return Optional.empty();
        }

        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Controller endpoint '%s' has no security annotations"
                        .formatted(endpoint.route()))
                .endpoint(endpoint)
                .recommendation("Add @PreAuthorize, @Secured, @RolesAllowed, or @PermitAll to explicitly define security")
                .build());
    }
}
