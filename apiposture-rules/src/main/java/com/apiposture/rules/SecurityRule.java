package com.apiposture.rules;

import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.Finding;
import com.apiposture.core.models.Severity;

import java.util.List;
import java.util.Optional;

/**
 * Interface for security rules that analyze endpoints for potential issues.
 */
public interface SecurityRule {

    /**
     * Get the unique identifier for this rule (e.g., "AP001").
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
     * Evaluate an endpoint and return a finding if the rule is violated.
     *
     * @param endpoint The endpoint to evaluate
     * @return Optional finding if the rule is violated, empty otherwise
     */
    Optional<Finding> evaluate(Endpoint endpoint);

    /**
     * Evaluate multiple endpoints and return all findings.
     *
     * @param endpoints The endpoints to evaluate
     * @return List of findings from violated rules
     */
    default List<Finding> evaluateAll(List<Endpoint> endpoints) {
        return endpoints.stream()
                .map(this::evaluate)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }

    /**
     * Check if this rule is enabled by default.
     */
    default boolean isEnabledByDefault() {
        return true;
    }
}
