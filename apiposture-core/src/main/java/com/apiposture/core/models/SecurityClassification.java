package com.apiposture.core.models;

/**
 * Security classification for endpoints based on their authorization configuration.
 */
public enum SecurityClassification {
    /**
     * No authorization required - anyone can access.
     */
    PUBLIC,

    /**
     * Requires authentication but no specific roles/policies.
     */
    AUTHENTICATED,

    /**
     * Requires specific roles (e.g., ADMIN, USER).
     */
    ROLE_RESTRICTED,

    /**
     * Requires specific policies/authorities.
     */
    POLICY_RESTRICTED;

    /**
     * Check if this classification indicates public access.
     */
    public boolean isPublic() {
        return this == PUBLIC;
    }

    /**
     * Check if this classification requires any form of authorization.
     */
    public boolean requiresAuthorization() {
        return this != PUBLIC;
    }

    /**
     * Parse classification from string, case-insensitive.
     * Handles both enum names and hyphenated versions.
     */
    public static SecurityClassification fromString(String value) {
        if (value == null || value.isBlank()) {
            return PUBLIC;
        }
        String normalized = value.toUpperCase().replace("-", "_");
        try {
            return SecurityClassification.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            return PUBLIC;
        }
    }
}
