package com.apiposture.core.discovery;

import com.apiposture.core.analysis.SourceFileLoader;
import com.apiposture.core.authorization.AnnotationAuthorizationExtractor;
import com.apiposture.core.models.Endpoint;
import com.apiposture.core.models.HttpMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ControllerEndpointDiscovererTest {

    private ControllerEndpointDiscoverer discoverer;
    private SourceFileLoader loader;

    @BeforeEach
    void setUp() {
        loader = new SourceFileLoader();
        discoverer = new ControllerEndpointDiscoverer(new AnnotationAuthorizationExtractor());
    }

    @Test
    void shouldDiscoverRestController() {
        var code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            @RequestMapping("/api/products")
            public class ProductsController {
                @GetMapping
                public String getAll() { return "products"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "ProductsController.java");

        assertThat(endpoints).hasSize(1);
        assertThat(endpoints.get(0).route()).isEqualTo("/api/products");
        assertThat(endpoints.get(0).methods()).containsExactly(HttpMethod.GET);
        assertThat(endpoints.get(0).controllerName()).isEqualTo("ProductsController");
        assertThat(endpoints.get(0).methodName()).isEqualTo("getAll");
    }

    @Test
    void shouldDiscoverMultipleMappings() {
        var code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            @RequestMapping("/api/items")
            public class ItemsController {
                @GetMapping
                public String getAll() { return "items"; }

                @GetMapping("/{id}")
                public String getById() { return "item"; }

                @PostMapping
                public String create() { return "created"; }

                @PutMapping("/{id}")
                public String update() { return "updated"; }

                @DeleteMapping("/{id}")
                public void delete() { }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "ItemsController.java");

        assertThat(endpoints).hasSize(5);
        assertThat(endpoints).extracting(Endpoint::route)
                .containsExactlyInAnyOrder(
                        "/api/items",
                        "/api/items/{id}",
                        "/api/items",
                        "/api/items/{id}",
                        "/api/items/{id}"
                );
    }

    @Test
    void shouldExtractHttpMethodFromRequestMapping() {
        var code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class TestController {
                @RequestMapping(value = "/test", method = RequestMethod.POST)
                public String test() { return "test"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "TestController.java");

        assertThat(endpoints).hasSize(1);
        assertThat(endpoints.get(0).methods()).containsExactly(HttpMethod.POST);
    }

    @Test
    void shouldHandleControllerAnnotation() {
        var code = """
            import org.springframework.stereotype.Controller;
            import org.springframework.web.bind.annotation.*;

            @Controller
            @RequestMapping("/pages")
            public class PagesController {
                @GetMapping("/home")
                public String home() { return "home"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "PagesController.java");

        assertThat(endpoints).hasSize(1);
        assertThat(endpoints.get(0).route()).isEqualTo("/pages/home");
    }

    @Test
    void shouldIgnoreNonControllerClasses() {
        var code = """
            public class SomeService {
                public String doSomething() { return "done"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "SomeService.java");

        assertThat(endpoints).isEmpty();
    }

    @Test
    void shouldHandleEmptyBasePath() {
        var code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class RootController {
                @GetMapping("/health")
                public String health() { return "ok"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "RootController.java");

        assertThat(endpoints).hasSize(1);
        assertThat(endpoints.get(0).route()).isEqualTo("/health");
    }

    @Test
    void shouldNormalizePathSlashes() {
        var code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            @RequestMapping("/api/")
            public class SlashController {
                @GetMapping("/items/")
                public String getItems() { return "items"; }
            }
            """;

        var cu = loader.parseText(code).orElseThrow();
        List<Endpoint> endpoints = discoverer.discover(cu, "SlashController.java");

        assertThat(endpoints).hasSize(1);
        assertThat(endpoints.get(0).route()).isEqualTo("/api/items");
    }
}
