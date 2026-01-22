package com.apiposture.rules;

import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.Finding;
import com.apiposture.core.models.ScanResult;
import com.apiposture.core.models.Severity;
import com.apiposture.rules.consistency.ControllerMethodConflictRule;
import com.apiposture.rules.consistency.MissingAuthOnWritesRule;
import com.apiposture.rules.exposure.PermitAllOnWriteRule;
import com.apiposture.rules.exposure.PublicWithoutExplicitIntentRule;
import com.apiposture.rules.privilege.ExcessiveRoleAccessRule;
import com.apiposture.rules.privilege.WeakRoleNamingRule;
import com.apiposture.rules.surface.ControllerWithoutAuthRule;
import com.apiposture.rules.surface.SensitiveRouteKeywordsRule;

import java.util.*;

/**
 * Engine that orchestrates security rule evaluation.
 */
public class RuleEngine {

    private final List<SecurityRule> rules;
    private final Set<String> disabledRules;
    private Severity minimumSeverity;

    public RuleEngine() {
        this.rules = new ArrayList<>();
        this.disabledRules = new HashSet<>();
        this.minimumSeverity = Severity.INFO;

        // Register all built-in rules
        registerBuiltInRules();
    }

    /**
     * Register all built-in security rules.
     */
    private void registerBuiltInRules() {
        // Exposure rules
        rules.add(new PublicWithoutExplicitIntentRule());  // AP001
        rules.add(new PermitAllOnWriteRule());             // AP002

        // Consistency rules
        rules.add(new ControllerMethodConflictRule());     // AP003
        rules.add(new MissingAuthOnWritesRule());          // AP004

        // Privilege rules
        rules.add(new ExcessiveRoleAccessRule());          // AP005
        rules.add(new WeakRoleNamingRule());               // AP006

        // Surface rules
        rules.add(new SensitiveRouteKeywordsRule());       // AP007
        rules.add(new ControllerWithoutAuthRule());        // AP008
    }

    /**
     * Add a custom rule to the engine.
     */
    public void addRule(SecurityRule rule) {
        rules.add(rule);
    }

    /**
     * Disable a rule by its ID.
     */
    public void disableRule(String ruleId) {
        disabledRules.add(ruleId);
    }

    /**
     * Enable a previously disabled rule.
     */
    public void enableRule(String ruleId) {
        disabledRules.remove(ruleId);
    }

    /**
     * Set minimum severity for reported findings.
     */
    public void setMinimumSeverity(Severity severity) {
        this.minimumSeverity = severity;
    }

    /**
     * Get all registered rules.
     */
    public List<SecurityRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    /**
     * Evaluate all endpoints against all enabled rules.
     */
    public List<Finding> evaluate(List<Endpoint> endpoints) {
        List<Finding> findings = new ArrayList<>();

        for (SecurityRule rule : rules) {
            // Skip disabled rules
            if (disabledRules.contains(rule.getId())) {
                continue;
            }

            // Evaluate each endpoint
            for (Endpoint endpoint : endpoints) {
                rule.evaluate(endpoint).ifPresent(finding -> {
                    // Only include if severity meets minimum threshold
                    if (finding.severity().isAtLeast(minimumSeverity)) {
                        findings.add(finding);
                    }
                });
            }
        }

        // Sort by severity (highest first), then by rule ID
        findings.sort(Comparator
                .comparing((Finding f) -> f.severity().getLevel()).reversed()
                .thenComparing(Finding::ruleId));

        return findings;
    }

    /**
     * Evaluate endpoints and create a complete scan result.
     */
    public ScanResult evaluateToScanResult(ScanResult analysisResult) {
        List<Finding> findings = evaluate(analysisResult.endpoints());

        return ScanResult.builder()
                .projectPath(analysisResult.projectPath())
                .endpoints(analysisResult.endpoints())
                .findings(findings)
                .scannedFiles(analysisResult.scannedFiles())
                .scanDuration(analysisResult.scanDuration())
                .timestamp(analysisResult.timestamp())
                .build();
    }

    /**
     * Get rule by ID.
     */
    public Optional<SecurityRule> getRule(String ruleId) {
        return rules.stream()
                .filter(r -> r.getId().equals(ruleId))
                .findFirst();
    }

    /**
     * Check if a specific rule is enabled.
     */
    public boolean isRuleEnabled(String ruleId) {
        return !disabledRules.contains(ruleId);
    }
}
