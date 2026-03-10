package com.apiposture.rules;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class KnownPublicRouteSegmentsTest {

    // --- Auth entry points ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/login",
            "/api/auth/login",
            "/admin/login",
            "/api/auth/signin",
            "/user/register",
            "/api/auth/signup",
            "/user/registration",
            "/api/users/activate",
            "/api/confirm/{token}",
            "/user/resetpassword",
            "/api/auth/resetPassword",
            "/user/savePassword",
            "/user/changePassword",
            "/api/auth/forgotPassword",
            "/user/logout",
            "/api/auth/signout"
    })
    void shouldRecognizeAuthEntryPoints(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isTrue();
    }

    // --- Infrastructure health probes ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/health",
            "/actuator/health",
            "/api/health",
            "/healthz",
            "/readiness",
            "/liveness",
            "/ping",
            "/ready",
            "/live"
    })
    void shouldRecognizeInfraProbes(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isTrue();
    }

    // --- Webhooks ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/payment/alipay/notify",
            "/aliyun/oss/callback",
            "/webhook",
            "/api/webhook/github"
    })
    void shouldRecognizeWebhookCallbacks(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isTrue();
    }

    // --- OAuth / SSO ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/oauth/authorize",
            "/oauth2/callback",
            "/sso/login",
            "/sso/token",
            "/api/sso/info"
    })
    void shouldRecognizeOAuthSsoFlows(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isTrue();
    }

    // --- Should NOT match (real endpoints that need auth) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/users",
            "/api/products",
            "/admin/users",
            "/admin/settings",
            "/api/orders/{id}",
            "/api/generator/tables",
            "/api/config/database"
    })
    void shouldNotMatchRegularEndpoints(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isFalse();
    }

    @Test
    void shouldReturnFalseForNullRoute() {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(null)).isFalse();
    }

    @Test
    void shouldReturnFalseForBlankRoute() {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("   ")).isFalse();
    }

    @Test
    void matchingIsCaseInsensitive() {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("/api/auth/LOGIN")).isTrue();
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("/api/auth/SignIn")).isTrue();
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("/HEALTH")).isTrue();
    }

    // --- Compound camelCase routes (starts-with / contains matching) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/user/registrationCaptcha",           // starts with "registration" (12 chars)
            "/user/registrationCaptchaV3",         // same
            "/old/registrationConfirm",            // starts with "registration"
            "/registrationConfirm",                // same
            "/user/resendRegistrationToken",       // contains "registration" (>= 10 chars)
            "/old/user/resendRegistrationToken"    // same
    })
    void shouldRecognizeCompoundRegistrationRoutes(String route) {
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint(route)).isTrue();
    }

    @Test
    void shouldNotMatchShortKeywordAsPrefix() {
        // Short segments like "login" (5 chars) are NOT used for starts-with matching,
        // so "loginHistory" must NOT be exempted.
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("/api/loginHistory")).isFalse();
    }

    @Test
    void shouldNotMatchKeywordEmbeddedInUnrelatedWord() {
        // "autoregister" starts with "auto", not "register" → not matched
        assertThat(KnownPublicRouteSegments.isKnownPublicEndpoint("/api/autoregister")).isFalse();
    }
}
