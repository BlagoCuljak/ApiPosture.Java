package com.apiposture.rules.consistency;

import com.apiposture.core.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class MissingAuthOnWritesRuleTest {

    private MissingAuthOnWritesRule rule;

    @BeforeEach
    void setUp() {
        rule = new MissingAuthOnWritesRule();
    }

    @ParameterizedTest
    @EnumSource(value = HttpMethod.class, names = {"POST", "PUT", "DELETE", "PATCH"})
    void shouldReturnCriticalFindingForPublicWriteMethod(HttpMethod method) {
        Endpoint endpoint = createEndpoint(method, SecurityClassification.PUBLIC,
                AuthorizationInfo.empty());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isPresent();
        assertThat(finding.get().ruleId()).isEqualTo("AP004");
        assertThat(finding.get().severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void shouldNotReturnFindingForPublicGetMethod() {
        Endpoint endpoint = createEndpoint(HttpMethod.GET, SecurityClassification.PUBLIC,
                AuthorizationInfo.empty());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    @Test
    void shouldNotReturnFindingForAuthenticatedPostMethod() {
        Endpoint endpoint = createEndpoint(HttpMethod.POST, SecurityClassification.AUTHENTICATED,
                AuthorizationInfo.builder().hasAuthorize(true).build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    @Test
    void shouldNotReturnFindingForPermitAllWrite() {
        // AP002 handles this case
        Endpoint endpoint = createEndpoint(HttpMethod.POST, SecurityClassification.PUBLIC,
                AuthorizationInfo.builder().hasPermitAll(true).build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    @Test
    void shouldNotReturnFindingForRoleRestrictedWrite() {
        Endpoint endpoint = createEndpoint(HttpMethod.POST, SecurityClassification.ROLE_RESTRICTED,
                AuthorizationInfo.builder().hasAuthorize(true).addRole("ADMIN").build());

        Optional<Finding> finding = rule.evaluate(endpoint);

        assertThat(finding).isEmpty();
    }

    private Endpoint createEndpoint(HttpMethod method, SecurityClassification classification,
                                    AuthorizationInfo auth) {
        return Endpoint.builder()
                .route("/api/test")
                .methods(EnumSet.of(method))
                .type(EndpointType.CONTROLLER)
                .controllerName("TestController")
                .methodName("test")
                .location(new SourceLocation("Test.java", 10))
                .authorization(auth)
                .classification(classification)
                .build();
    }
}
