package com.apiposture.rules.surface;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ControllerWithoutAuthRuleTest {

    private ControllerWithoutAuthRule rule;

    @BeforeEach
    void setUp() {
        rule = new ControllerWithoutAuthRule();
    }

    @Test
    void shouldFlagControllerEndpointWithNoAnnotations() {
        Endpoint endpoint = createEndpoint("/api/products", AuthorizationInfo.empty());
        Optional<Finding> finding = rule.evaluate(endpoint);
        assertThat(finding).isPresent();
        assertThat(finding.get().ruleId()).isEqualTo("AP008");
        assertThat(finding.get().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void shouldNotFlagEndpointWithPreAuthorize() {
        Endpoint endpoint = createEndpoint("/api/products",
                AuthorizationInfo.builder().hasAuthorize(true).addRole("USER").build());
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    @Test
    void shouldNotFlagEndpointWithPermitAll() {
        Endpoint endpoint = createEndpoint("/api/products",
                AuthorizationInfo.builder().hasPermitAll(true).build());
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    @Test
    void shouldNotFlagEndpointWithDenyAll() {
        Endpoint endpoint = createEndpoint("/api/internal",
                AuthorizationInfo.builder().hasDenyAll(true).build());
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    // --- Known public endpoints should not be flagged (false-positive prevention) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/login",
            "/api/auth/login",
            "/api/auth/signin",
            "/api/auth/signup",
            "/user/register",
            "/user/registration",
            "/api/auth/resetPassword",
            "/health",
            "/actuator/health",
            "/healthz",
            "/readiness",
            "/liveness",
            "/ping",
            "/payment/alipay/notify",
            "/aliyun/oss/callback",
            "/webhook",
            "/oauth/authorize",
            "/sso/login"
    })
    void shouldNotFlagKnownPublicEndpoints(String route) {
        Endpoint endpoint = createEndpoint(route, AuthorizationInfo.empty());
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    @Test
    void messageShouldIncludeRoute() {
        Endpoint endpoint = createEndpoint("/api/orders", AuthorizationInfo.empty());
        Optional<Finding> finding = rule.evaluate(endpoint);
        assertThat(finding).isPresent();
        assertThat(finding.get().message()).contains("/api/orders");
    }

    private Endpoint createEndpoint(String route, AuthorizationInfo auth) {
        return Endpoint.builder()
                .route(route)
                .methods(EnumSet.of(HttpMethod.GET))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("test")
                .location(new SourceLocation("TestController.java", 10))
                .authorization(auth)
                .classification(SecurityClassification.PUBLIC)
                .build();
    }
}
