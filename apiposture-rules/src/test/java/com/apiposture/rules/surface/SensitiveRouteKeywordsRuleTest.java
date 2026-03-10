package com.apiposture.rules.surface;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveRouteKeywordsRuleTest {

    private SensitiveRouteKeywordsRule rule;

    @BeforeEach
    void setUp() {
        rule = new SensitiveRouteKeywordsRule();
    }

    // --- Should fire ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/admin/users",
            "/admin/settings",
            "/api/admin/roles",
            "/internal/metrics",
            "/api/actuator/env",
            "/api/config/database",
            "/export/data",
            "/api/backup/create"
    })
    void shouldFlagSensitiveKeywordOnPublicEndpoint(String route) {
        Endpoint endpoint = publicEndpoint(route);
        Optional<Finding> finding = rule.evaluate(endpoint);
        assertThat(finding).isPresent();
        assertThat(finding.get().ruleId()).isEqualTo("AP007");
        assertThat(finding.get().severity()).isEqualTo(Severity.MEDIUM);
    }

    // --- Should NOT fire: non-public endpoints ---

    @Test
    void shouldNotFlagAuthenticatedEndpointWithSensitiveKeyword() {
        Endpoint endpoint = Endpoint.builder()
                .route("/admin/users")
                .methods(EnumSet.of(HttpMethod.GET))
                .type(EndpointType.CONTROLLER)
                .controllerName("AdminController")
                .methodName("listUsers")
                .location(new SourceLocation("AdminController.java", 20))
                .authorization(AuthorizationInfo.builder().hasAuthorize(true).addRole("ADMIN").build())
                .classification(SecurityClassification.ROLE_RESTRICTED)
                .build();
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    // --- Should NOT fire: health and info keywords removed ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/health",
            "/actuator/health",
            "/api/health",
            "/healthz"
    })
    void shouldNotFlagHealthEndpoints(String route) {
        // health is intentionally public (K8s probes etc.) — removed from SENSITIVE_KEYWORDS
        Endpoint endpoint = publicEndpoint(route);
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/auth/info",            // auth server discovery endpoint, public by design
            "/sso/info",             // SSO discovery, already handled by known-public check too
            "/api/info",             // standalone info; "actuator" keyword covers actuator/info
            "/system/info"
    })
    void shouldNotFlagInfoEndpoints(String route) {
        // "info" removed from SENSITIVE_KEYWORDS — noisy keyword, /actuator covers the real risk
        Endpoint endpoint = publicEndpoint(route);
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    // --- Should NOT fire: word boundary fix (compound identifiers) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/productAttribute/attrInfo",         // "info" embedded in "attrInfo"
            "/order/update/receiverInfo",          // "info" embedded in "receiverInfo"
            "/product/updateInfo",                 // "info" embedded in "updateInfo"
            "/sso/refreshToken",                   // "token" embedded in "refreshToken"
            "/api/genConfig/{tableName}",          // "config" embedded in "genConfig"
            "/api/generator/tableMetaInfo"         // "info" embedded in "tableMetaInfo"
    })
    void shouldNotFlagKeywordEmbeddedInCompoundIdentifier(String route) {
        Endpoint endpoint = publicEndpoint(route);
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    // --- Should NOT fire: known public endpoints ---

    @ParameterizedTest
    @ValueSource(strings = {
            "/admin/login",                        // admin keyword, but login makes it known-public
            "/sso/info",                           // info keyword, but sso makes it known-public
            "/api/auth/token",                     // token keyword, but auth/token is OAuth
            "/user/resetPassword",                 // password keyword, but reset flow is public
            "/user/changePassword",                // password keyword, but change flow is public
            "/actuator/health",                    // health removed AND health probe segment
            "/alipay/notify"                       // notify is a known webhook pattern
    })
    void shouldNotFlagKnownPublicEndpoints(String route) {
        Endpoint endpoint = publicEndpoint(route);
        assertThat(rule.evaluate(endpoint)).isEmpty();
    }

    // --- Message content ---

    @Test
    void messageShouldIncludeRouteAndKeyword() {
        Endpoint endpoint = publicEndpoint("/api/admin/users");
        Optional<Finding> finding = rule.evaluate(endpoint);
        assertThat(finding).isPresent();
        assertThat(finding.get().message()).contains("/api/admin/users");
        assertThat(finding.get().message()).contains("admin");
    }

    private Endpoint publicEndpoint(String route) {
        return Endpoint.builder()
                .route(route)
                .methods(EnumSet.of(HttpMethod.GET))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("test")
                .location(new SourceLocation("TestController.java", 10))
                .authorization(AuthorizationInfo.empty())
                .classification(SecurityClassification.PUBLIC)
                .build();
    }
}
