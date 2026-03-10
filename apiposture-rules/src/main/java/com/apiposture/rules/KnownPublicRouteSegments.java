package com.apiposture.rules;

import java.util.Set;

/**
 * Shared utility identifying endpoint routes that are known to be intentionally public.
 *
 * <p>Used by AP001, AP004, AP007, and AP008 to suppress false positives on well-established
 * public patterns: auth entry points, infrastructure health probes, payment/service webhooks,
 * and OAuth/SSO flows. Any new rule that would otherwise flag public endpoints should call
 * {@link #isKnownPublicEndpoint(String)} before yielding a finding.</p>
 */
public final class KnownPublicRouteSegments {

    /** Auth entry points — always intentionally public (login, register, password-reset flow). */
    static final Set<String> AUTH_ENTRY_SEGMENTS = Set.of(
            "login", "signin", "logout", "signout",
            "register", "signup", "registration",
            "activate", "verify", "confirm", "confirmation",
            "resetpassword", "forgotpassword", "changepassword",
            "savepassword", "updatepassword"
    );

    /** Infrastructure/readiness probes — always intentionally public (K8s, cloud health checks). */
    static final Set<String> INFRA_PROBE_SEGMENTS = Set.of(
            "health", "healthz", "readiness", "liveness",
            "ping", "ready", "live"
    );

    /** Payment/service webhook callbacks — must accept unauthenticated inbound POSTs. */
    static final Set<String> WEBHOOK_SEGMENTS = Set.of(
            "notify", "webhook", "callback"
    );

    /** OAuth/SSO flow segments — token exchange and SSO redirects are intentionally public. */
    static final Set<String> OAUTH_SEGMENTS = Set.of(
            "oauth", "oauth2", "sso", "token"
    );

    private static final Set<String> ALL_KNOWN_PUBLIC;

    /**
     * Known segments long enough (>= 7 chars) to safely use as a starts-with prefix check.
     * Covers camelCase compound routes like {@code registrationCaptcha}, {@code registrationConfirm}.
     */
    private static final Set<String> LONG_PREFIX_SEGMENTS;

    /**
     * Known segments long enough (>= 10 chars) to safely use as a contains check.
     * Covers compound routes like {@code resendRegistrationToken} that embed a long known segment
     * somewhere in the middle.
     */
    private static final Set<String> LONG_CONTAINS_SEGMENTS;

    static {
        var all = new java.util.HashSet<String>();
        all.addAll(AUTH_ENTRY_SEGMENTS);
        all.addAll(INFRA_PROBE_SEGMENTS);
        all.addAll(WEBHOOK_SEGMENTS);
        all.addAll(OAUTH_SEGMENTS);
        ALL_KNOWN_PUBLIC = Set.copyOf(all);

        var prefixes = new java.util.HashSet<String>();
        var contains = new java.util.HashSet<String>();
        for (String s : ALL_KNOWN_PUBLIC) {
            if (s.length() >= 7)  prefixes.add(s);
            if (s.length() >= 10) contains.add(s);
        }
        LONG_PREFIX_SEGMENTS  = Set.copyOf(prefixes);
        LONG_CONTAINS_SEGMENTS = Set.copyOf(contains);
    }

    private KnownPublicRouteSegments() {}

    /**
     * Returns {@code true} if any path segment in {@code route} matches a known public pattern
     * (case-insensitive). Matching uses three strategies in order:
     *
     * <ol>
     *   <li><b>Exact match</b> — the segment equals a known public term (e.g. {@code login}).</li>
     *   <li><b>Starts-with</b> — the segment starts with a known term of ≥ 7 chars, covering
     *       camelCase compound routes like {@code registrationCaptcha} or {@code registrationConfirm}.</li>
     *   <li><b>Contains</b> — the segment contains a known term of ≥ 10 chars, covering routes
     *       like {@code resendRegistrationToken} where the known word is embedded in the middle.</li>
     * </ol>
     *
     * <p>Examples that return {@code true}:</p>
     * <ul>
     *   <li>{@code /api/auth/login}, {@code /admin/login}</li>
     *   <li>{@code /user/registrationCaptcha}, {@code /old/registrationConfirm}</li>
     *   <li>{@code /user/resendRegistrationToken}</li>
     *   <li>{@code /actuator/health}, {@code /healthz}</li>
     *   <li>{@code /payment/alipay/notify}, {@code /webhook}</li>
     *   <li>{@code /sso/token}, {@code /oauth2/callback}</li>
     * </ul>
     */
    public static boolean isKnownPublicEndpoint(String route) {
        if (route == null || route.isBlank()) {
            return false;
        }
        for (String raw : route.split("[/{?&=}]+")) {
            if (raw.isBlank()) continue;
            String seg = raw.toLowerCase();
            // 1. Exact match
            if (ALL_KNOWN_PUBLIC.contains(seg)) return true;
            // 2. Starts-with a long known segment (handles registrationCaptcha, registrationConfirm)
            for (String prefix : LONG_PREFIX_SEGMENTS) {
                if (seg.startsWith(prefix)) return true;
            }
            // 3. Contains a very long known segment (handles resendRegistrationToken)
            for (String needle : LONG_CONTAINS_SEGMENTS) {
                if (seg.contains(needle)) return true;
            }
        }
        return false;
    }
}
