package com.apiposture.rules.exposure;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
