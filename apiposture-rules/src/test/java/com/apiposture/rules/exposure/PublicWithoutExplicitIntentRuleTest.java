package com.apiposture.rules.exposure;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PublicWithoutExplicitIntentRuleTest {

    private PublicWithoutExplicitIntentRule rule;

    @BeforeEach
    void setUp() {
        rule = new PublicWithoutExplicitIntentRule();
    }

    @Test
    void shouldReturnFindingForPublicWithoutPermitAll() {
        Endpoint endpoint = createEndpoint(SecurityClassification.PUBLIC,
                AuthorizationInfo.empty());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isPresent();
        assertThat(finding.get().ruleId()).isEqualTo("AP001");
        assertThat(finding.get().severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void shouldNotReturnFindingForPublicWithPermitAll() {
        Endpoint endpoint = createEndpoint(SecurityClassification.PUBLIC,
                AuthorizationInfo.builder().hasPermitAll(true).build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    @Test
    void shouldNotReturnFindingForAuthenticatedEndpoint() {
        Endpoint endpoint = createEndpoint(SecurityClassification.AUTHENTICATED,
                AuthorizationInfo.builder().hasAuthorize(true).build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    @Test
    void shouldNotReturnFindingForRoleRestrictedEndpoint() {
        Endpoint endpoint = createEndpoint(SecurityClassification.ROLE_RESTRICTED,
                AuthorizationInfo.builder().hasAuthorize(true).addRole("ADMIN").build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    // --- Known-public endpoint exemptions (false-positive prevention) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/login",
            "/api/auth/login",
            "/api/auth/signin",
            "/api/auth/signup",
            "/user/register",
            "/user/registration",
            "/user/registrationCaptcha",
            "/user/registrationCaptchaV3",
            "/old/registrationConfirm",
            "/user/resendRegistrationToken",
            "/api/auth/resetPassword",
            "/admin/login",
            "/sso/login",
            "/health",
            "/actuator/health",
            "/healthz",
            "/readiness",
            "/liveness",
            "/ping",
            "/payment/alipay/notify",
            "/webhook",
            "/oauth/authorize",
            "/sso/token"
    })
    void shouldNotReturnFindingForKnownPublicEndpoints(String route) {
        Endpoint endpoint = Endpoint.builder()
                .route(route)
                .methods(EnumSet.of(HttpMethod.GET))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("test")
                .location(new SourceLocation("Test.java", 10))
                .authorization(AuthorizationInfo.empty())
                .classification(SecurityClassification.PUBLIC)
                .build();

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    private Endpoint createEndpoint(SecurityClassification classification, AuthorizationInfo auth) {
        return Endpoint.builder()
                .route("/api/test")
                .methods(EnumSet.of(HttpMethod.GET))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("test")
                .location(new SourceLocation("Test.java", 10))
                .authorization(auth)
                .classification(classification)
                .build();
    }
}
