package com.apiposture.rules.consistency;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;

/**
 * AP003: Detects when method-level @PermitAll overrides class-level authorization.
 * This pattern can lead to unintended security holes.
 */
public class ControllerMethodConflictRule implements SecurityRule {

    @Override
    public String getId() {
        return "AP003";
    }

    @Override
    public String getName() {
        return "Controller/method authorization conflict";
    }

    @Override
    public String getDescription() {
        return "Detects when method-level @PermitAll overrides class-level authorization, " +
                "which may indicate unintended security bypass.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        AuthorizationInfo auth = endpoint.authorization();

        if (auth == null) {
            return Optional.empty();
        }

        // Check if method has @PermitAll and inherited class auth
        if (auth.hasPermitAll() && auth.isInherited()) {
            return Optional.of(Finding.builder()
                    .ruleId(getId())
                    .ruleName(getName())
                    .severity(getDefaultSeverity())
                    .message("Endpoint '%s' has @PermitAll that overrides class-level authorization"
                            .formatted(endpoint.route()))
                    .endpoint(endpoint)
                    .recommendation("Review if this override is intentional. Consider documenting the security decision.")
                    .build());
        }

        // Also check for explicit permit all with class-level auth indicator
        // This happens when the inheritance flag is set from class level
        if (auth.hasPermitAll() && "class".equals(auth.getInheritedFrom())) {
            return Optional.empty(); // This is actually the case where class auth was overridden properly
        }

        return Optional.empty();
    }
}
