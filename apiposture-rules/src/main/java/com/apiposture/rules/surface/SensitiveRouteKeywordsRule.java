package com.apiposture.rules.surface;

import com.apiposture.core.models.*;
import com.apiposture.rules.KnownPublicRouteSegments;
import com.apiposture.rules.SecurityRule;

import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * AP007: Detects sensitive keywords in public routes.
 * Routes containing admin, debug, export, etc. should not be public.
 */
public class SensitiveRouteKeywordsRule implements SecurityRule {

    // "health" removed: health-check endpoints are public by convention (K8s probes, etc.)
    // "info" removed: too noisy — standalone /info is already caught by "actuator" when it's an
    //   actuator endpoint, and /auth/info or /sso/info are intentional public discovery endpoints.
    //   Compound uses like "attrInfo", "receiverInfo" are also handled by word-boundary matching.
    private static final Set<String> SENSITIVE_KEYWORDS = Set.of(
            "admin", "debug", "export", "import", "backup", "restore",
            "config", "configuration", "settings", "internal", "private",
            "secret", "key", "credential",
            "management", "actuator", "metrics"
    );

    // Word-boundary anchors prevent matching keywords embedded in compound identifiers
    // (e.g. "info" inside "attrInfo", "token" inside "refreshToken", "config" inside "genConfig")
    private static final Pattern KEYWORD_PATTERN = Pattern.compile(
            "(?i)(?<![a-z])(" + String.join("|", SENSITIVE_KEYWORDS) + ")(?![a-z])"
    );

    @Override
    public String getId() {
        return "AP007";
    }

    @Override
    public String getName() {
        return "Sensitive route keywords";
    }

    @Override
    public String getDescription() {
        return "Detects public routes containing sensitive keywords like 'admin', 'debug', " +
                "'export' that may indicate privileged functionality.";
    }

    @Override
    public Severity getDefaultSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public Optional<Finding> evaluate(Endpoint endpoint) {
        // Only check public endpoints
        if (endpoint.classification() != SecurityClassification.PUBLIC) {
            return Optional.empty();
        }

        // Skip known-public routes — keywords like "admin" in /admin/login or "info" in
        // /sso/info are intentional; flagging them would be noise, not signal.
        if (KnownPublicRouteSegments.isKnownPublicEndpoint(endpoint.route())) {
            return Optional.empty();
        }

        String route = endpoint.route().toLowerCase();
        var matcher = KEYWORD_PATTERN.matcher(route);

        if (!matcher.find()) {
            return Optional.empty();
        }

        String keyword = matcher.group(1);

        return Optional.of(Finding.builder()
                .ruleId(getId())
                .ruleName(getName())
                .severity(getDefaultSeverity())
                .message("Public endpoint '%s' contains sensitive keyword '%s'"
                        .formatted(endpoint.route(), keyword))
                .endpoint(endpoint)
                .recommendation("Add authorization to this endpoint or move to a secured path")
                .build());
    }
}
