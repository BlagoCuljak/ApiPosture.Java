package com.apiposture.core.classification;

import com.apiposture.core.models.AuthorizationInfo;
import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.SecurityClassification;

/**
 * Classifies endpoints based on their authorization configuration.
 */
public class SecurityClassifier {

    /**
     * Classify an endpoint based on its authorization info.
     */
    public Endpoint classify(Endpoint endpoint) {
        SecurityClassification classification = determineClassification(endpoint.authorization());
        return endpoint.withClassification(classification);
    }

    /**
     * Determine the security classification from authorization info.
     */
    public SecurityClassification determineClassification(AuthorizationInfo auth) {
        if (auth == null) {
            return SecurityClassification.PUBLIC;
        }

        // Explicit @PermitAll means public access
        if (auth.hasPermitAll()) {
            return SecurityClassification.PUBLIC;
        }

        // @DenyAll means no access - treat as most restrictive
        if (auth.hasDenyAll()) {
            return SecurityClassification.POLICY_RESTRICTED;
        }

        // Check for role-based restrictions
        if (!auth.getRoles().isEmpty()) {
            return SecurityClassification.ROLE_RESTRICTED;
        }

        // Check for authority/policy-based restrictions
        if (!auth.getAuthorities().isEmpty()) {
            return SecurityClassification.POLICY_RESTRICTED;
        }

        // Has authorization requirement but no specific roles/policies
        if (auth.hasAuthorize() || auth.isAuthenticated()) {
            return SecurityClassification.AUTHENTICATED;
        }

        // No security annotations - public by default
        return SecurityClassification.PUBLIC;
    }
}
