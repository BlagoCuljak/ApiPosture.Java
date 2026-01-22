package com.apiposture.rules;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RuleEngineTest {

    private RuleEngine engine;

    @BeforeEach
    void setUp() {
        engine = new RuleEngine();
    }

    @Test
    void shouldRegisterAllBuiltInRules() {
        List<SecurityRule> rules = engine.getRules();

        assertThat(rules).hasSize(8);
        assertThat(rules).extracting(SecurityRule::getId)
                .containsExactlyInAnyOrder(
                        "AP001", "AP002", "AP003", "AP004",
                        "AP005", "AP006", "AP007", "AP008"
                );
    }

    @Test
    void shouldDisableRule() {
        engine.disableRule("AP001");

        assertThat(engine.isRuleEnabled("AP001")).isFalse();
        assertThat(engine.isRuleEnabled("AP002")).isTrue();
    }

    @Test
    void shouldReEnableRule() {
        engine.disableRule("AP001");
        engine.enableRule("AP001");

        assertThat(engine.isRuleEnabled("AP001")).isTrue();
    }

    @Test
    void shouldEvaluateEndpoints() {
        Endpoint publicEndpoint = createEndpoint("/api/products", HttpMethod.GET,
                AuthorizationInfo.empty(), SecurityClassification.PUBLIC);

        List<Finding> findings = engine.evaluate(List.of(publicEndpoint));

        assertThat(findings).isNotEmpty();
        assertThat(findings).extracting(Finding::ruleId)
                .contains("AP001", "AP008");
    }

    @Test
    void shouldFilterByMinimumSeverity() {
        engine.setMinimumSeverity(Severity.HIGH);

        Endpoint endpoint = createEndpoint("/api/test", HttpMethod.GET,
                AuthorizationInfo.builder()
                        .hasAuthorize(true)
                        .addRole("User")
                        .addRole("Admin")
                        .addRole("Manager")
                        .addRole("Guest")
                        .addRole("Member")
                        .build(),
                SecurityClassification.ROLE_RESTRICTED);

        List<Finding> findings = engine.evaluate(List.of(endpoint));

        // AP005 (excessive roles) and AP006 (weak naming) are LOW severity
        assertThat(findings).allMatch(f -> f.severity().isAtLeast(Severity.HIGH));
    }

    @Test
    void shouldSortFindingsBySeverity() {
        Endpoint publicWrite = createEndpoint("/api/products", HttpMethod.POST,
                AuthorizationInfo.empty(), SecurityClassification.PUBLIC);
        Endpoint publicGet = createEndpoint("/api/items", HttpMethod.GET,
                AuthorizationInfo.empty(), SecurityClassification.PUBLIC);

        List<Finding> findings = engine.evaluate(List.of(publicWrite, publicGet));

        // First findings should be higher severity
        if (findings.size() >= 2) {
            assertThat(findings.get(0).severity().getLevel())
                    .isGreaterThanOrEqualTo(findings.get(1).severity().getLevel());
        }
    }

    @Test
    void shouldNotIncludeDisabledRuleFindings() {
        engine.disableRule("AP001");
        engine.disableRule("AP008");

        Endpoint endpoint = createEndpoint("/api/test", HttpMethod.GET,
                AuthorizationInfo.empty(), SecurityClassification.PUBLIC);

        List<Finding> findings = engine.evaluate(List.of(endpoint));

        assertThat(findings).extracting(Finding::ruleId)
                .doesNotContain("AP001", "AP008");
    }

    @Test
    void shouldGetRuleById() {
        var rule = engine.getRule("AP001");

        assertThat(rule).isPresent();
        assertThat(rule.get().getName()).isEqualTo("Public without explicit intent");
    }

    @Test
    void shouldReturnEmptyForUnknownRule() {
        var rule = engine.getRule("UNKNOWN");

        assertThat(rule).isEmpty();
    }

    private Endpoint createEndpoint(String route, HttpMethod method,
                                    AuthorizationInfo auth, SecurityClassification classification) {
        return Endpoint.builder()
                .route(route)
                .methods(EnumSet.of(method))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("testMethod")
                .location(new SourceLocation("Test.java", 10))
                .authorization(auth)
                .classification(classification)
                .build();
    }
}
