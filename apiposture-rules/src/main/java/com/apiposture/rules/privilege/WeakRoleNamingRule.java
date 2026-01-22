package com.apiposture.rules.privilege;

import com.apiposture.core.models.*;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;
import java.util.Set;

/**
 * AP006: Detects generic or weak role names like "User", "Admin".
 * Role names should be specific and descriptive.
 */
public class WeakRoleNamingRule implements SecurityRule {

    private static final Set<String> WEAK_ROLE_PATTERNS = Set.of(
            "user", "admin", "manager", "guest", "member",
            "role_user", "role_admin", "role_manager", "role_guest", "role_member"
    );

    @Override
    public String getId() {
        return "AP006";
    }

    @Override
    public String getName() {
        return "Weak role naming";
    }

    @Override
    public String getDescription() {
        return "Detects generic role names like 'User', 'Admin' that lack specificity " +
                "and may lead to overly broad access grants.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.LOW;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        AuthorizationInfo auth = endpoint.authorization();

        if (auth == null || auth.getRoles().isEmpty()) {
            return Optional.empty();
        }

        Set<String> weakRolesFound = auth.getRoles().stream()
                .filter(role -> WEAK_ROLE_PATTERNS.contains(role.toLowerCase()))
                .collect(java.util.stream.Collectors.toSet());

        if (weakRolesFound.isEmpty()) {
            return Optional.empty();
        }

        String weakRoles = String.join(", ", weakRolesFound);

        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Endpoint '%s' uses generic role names: %s"
                        .formatted(endpoint.route(), weakRoles))
                .endpoint(endpoint)
                .recommendation("Use more specific role names that describe the actual permission " +
                        "(e.g., 'PRODUCTS_MANAGER' instead of 'Admin')")
                .build());
    }
}
