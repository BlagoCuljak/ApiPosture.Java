package com.apiposture.core.extensions;

import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.Finding;
import com.apiposture.core.models.Severity;

import java.util.Optional;

/**
 * Interface for extension-provided security rules.
 * This allows Pro/Enterprise features to add custom rules.
 */
public interface ExtensionRule {

    /**
     * Get the unique identifier for this rule.
     * Should be in format "EXT001", "EXT002", etc.
     */
    String getId();

    /**
     * Get the human-readable name of this rule.
     */
    String getName();

    /**
     * Get the description of what this rule checks.
     */
    String getDescription();

    /**
     * Get the default severity for findings from this rule.
     */
    Severity getDefaultSeverity();

    /**
     * Get the extension that provides this rule.
     */
    String getExtensionId();

    /**
     * Evaluate an endpoint and return a finding if the rule is violated.
     *
     * @param endpoint The endpoint to evaluate
     * @return Optional finding if the rule is violated, empty otherwise
     */
    Optional<Finding> evaluate(Endpoint endpoint);

    /**
     * Check if this rule requires a Pro license.
     */
    default boolean requiresProLicense() {
        return true;
    }
}
