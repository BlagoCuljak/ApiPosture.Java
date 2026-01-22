package com.apiposture.core.authorization;

import com.apiposture.core.analysis.SourceFileLoader;
import com.apiposture.core.models.AuthorizationInfo;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AnnotationAuthorizationExtractorTest {

    private AnnotationAuthorizationExtractor extractor;
    private SourceFileLoader loader;

    @BeforeEach
    void setUp() {
        extractor = new AnnotationAuthorizationExtractor();
        loader = new SourceFileLoader();
    }

    @Test
    void shouldExtractPreAuthorizeWithRole() {
        var code = """
            import org.springframework.security.access.prepost.PreAuthorize;

            public class TestController {
                @PreAuthorize("hasRole('ADMIN')")
                public void adminOnly() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getRoles()).containsExactly("ADMIN");
    }

    @Test
    void shouldExtractPreAuthorizeWithMultipleRoles() {
        var code = """
            import org.springframework.security.access.prepost.PreAuthorize;

            public class TestController {
                @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
                public void adminOrManager() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getRoles()).containsExactlyInAnyOrder("ADMIN", "MANAGER");
    }

    @Test
    void shouldExtractPreAuthorizeWithAuthority() {
        var code = """
            import org.springframework.security.access.prepost.PreAuthorize;

            public class TestController {
                @PreAuthorize("hasAuthority('PRODUCTS_READ')")
                public void readProducts() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getAuthorities()).containsExactly("PRODUCTS_READ");
    }

    @Test
    void shouldExtractIsAuthenticated() {
        var code = """
            import org.springframework.security.access.prepost.PreAuthorize;

            public class TestController {
                @PreAuthorize("isAuthenticated()")
                public void authenticated() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void shouldExtractSecured() {
        var code = """
            import org.springframework.security.access.annotation.Secured;

            public class TestController {
                @Secured({"ROLE_USER", "ROLE_ADMIN"})
                public void secured() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getRoles()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void shouldExtractRolesAllowed() {
        var code = """
            import jakarta.annotation.security.RolesAllowed;

            public class TestController {
                @RolesAllowed("ADMIN")
                public void rolesAllowed() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getRoles()).containsExactly("ADMIN");
    }

    @Test
    void shouldExtractPermitAll() {
        var code = """
            import jakarta.annotation.security.PermitAll;

            public class TestController {
                @PermitAll
                public void publicEndpoint() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasPermitAll()).isTrue();
    }

    @Test
    void shouldExtractDenyAll() {
        var code = """
            import jakarta.annotation.security.DenyAll;

            public class TestController {
                @DenyAll
                public void denyAll() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasDenyAll()).isTrue();
    }

    @Test
    void shouldExtractClassLevelAnnotation() {
        var code = """
            import org.springframework.security.access.prepost.PreAuthorize;

            @PreAuthorize("hasRole('ADMIN')")
            public class AdminController {
                public void adminMethod() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var classDecl = cu.findFirst(ClassOrInterfaceDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(classDecl);

        assertThat(auth.hasAuthorize()).isTrue();
        assertThat(auth.getRoles()).containsExactly("ADMIN");
    }

    @Test
    void shouldReturnEmptyForNoAnnotations() {
        var code = """
            public class TestController {
                public void noAuth() {}
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        var method = cu.findFirst(MethodDeclaration.class).orElseThrow();

        AuthorizationInfo auth = extractor.extract(method);

        assertThat(auth.hasAuthorize()).isFalse();
        assertThat(auth.hasPermitAll()).isFalse();
        assertThat(auth.getRoles()).isEmpty();
        assertThat(auth.getAuthorities()).isEmpty();
    }
}
