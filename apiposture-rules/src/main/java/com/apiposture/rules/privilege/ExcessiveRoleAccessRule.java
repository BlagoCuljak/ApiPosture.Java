package com.apiposture.rules.privilege;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP005: Detects endpoints with excessive number of roles (>3).
 * Too many roles may indicate overly permissive access.
 */
public class ExcessiveRoleAccessRule implements SecurityRule {

    private static final int MAX_RECOMMENDED_ROLES = 3;

    @Override
    public String getId() {
        return "AP005";
    }

    @Override
    public String getName() {
        return "Excessive role access";
    }

    @Override
    public String getDescription() {
        return "Detects endpoints with more than " + MAX_RECOMMENDED_ROLES + " roles, " +
                "which may indicate overly permissive access or need for refactoring.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.LOW;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        AuthorizationInfo auth = endpoint.authorization();

        if (auth == null) {
            return Optional.empty();
        }

        int roleCount = auth.getRoles().size();

        if (roleCount <= MAX_RECOMMENDED_ROLES) {
            return Optional.empty();
        }

        String roles = String.join(", ", auth.getRoles());

        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Endpoint '%s' has %d roles: %s"
                        .formatted(endpoint.route(), roleCount, roles))
                .endpoint(endpoint)
                .recommendation("Consider consolidating roles or using policies to simplify access control")
                .build());
    }
}
