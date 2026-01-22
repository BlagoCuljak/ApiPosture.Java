package com.apiposture.core.discovery;

import com.apiposture.core.authorization.AnnotationAuthorizationExtractor;
import com.apiposture.core.models.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;

import java.util.*;

/**
 * Discovers endpoints from Spring MVC controllers.
 * Detects @RestController, @Controller, and request mapping annotations.
 */
public class ControllerEndpointDiscoverer implements EndpointDiscoverer {

    private static final Set<String> CONTROLLER_ANNOTATIONS = Set.of(
            "RestController", "Controller"
    );

    private static final Set<String> REQUEST_MAPPING_ANNOTATIONS = Set.of(
            "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
            "DeleteMapping", "PatchMapping"
    );

    private static final Map<String, HttpMethod> ANNOTATION_TO_METHOD = Map.of(
            "GetMapping", HttpMethod.GET,
            "PostMapping", HttpMethod.POST,
            "PutMapping", HttpMethod.PUT,
            "DeleteMapping", HttpMethod.DELETE,
            "PatchMapping", HttpMethod.PATCH
    );

    private final AnnotationAuthorizationExtractor authExtractor;

    public ControllerEndpointDiscoverer(AnnotationAuthorizationExtractor authExtractor) {
        this.authExtractor = authExtractor;
    }

    @Override
    public List<Endpoint> discover(CompilationUnit compilationUnit, String filePath) {
        List<Endpoint> endpoints = new ArrayList<>();

        compilationUnit.findAll(ClassOrInterfaceDeclaration.class).stream()
                .filter(this::isController)
                .forEach(controller -> {
                    String controllerName = controller.getNameAsString();
                    String basePath = extractRequestMappingPath(controller);
                    AuthorizationInfo classAuth = authExtractor.extract(controller);

                    controller.getMethods().stream()
                            .filter(this::hasRequestMapping)
                            .forEach(method -> {
                                Endpoint endpoint = createEndpoint(
                                        controller, method, controllerName, basePath,
                                        classAuth, filePath
                                );
                                endpoints.add(endpoint);
                            });
                });

        return endpoints;
    }

    /**
     * Check if a class is a Spring controller.
     */
    private boolean isController(ClassOrInterfaceDeclaration classDecl) {
        return classDecl.getAnnotations().stream()
                .anyMatch(a -> CONTROLLER_ANNOTATIONS.contains(a.getNameAsString()));
    }

    /**
     * Check if a method has any request mapping annotation.
     */
    private boolean hasRequestMapping(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .anyMatch(a -> REQUEST_MAPPING_ANNOTATIONS.contains(a.getNameAsString()));
    }

    /**
     * Extract the path from @RequestMapping on a class or method.
     */
    private String extractRequestMappingPath(NodeWithAnnotations<?> node) {
        return node.getAnnotations().stream()
                .filter(a -> REQUEST_MAPPING_ANNOTATIONS.contains(a.getNameAsString()))
                .findFirst()
                .map(this::extractPathFromAnnotation)
                .orElse("");
    }

    /**
     * Extract path value from a mapping annotation.
     */
    private String extractPathFromAnnotation(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            return extractStringValue(single.getMemberValue());
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            return normal.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("value") || p.getNameAsString().equals("path"))
                    .findFirst()
                    .map(p -> extractStringValue(p.getValue()))
                    .orElse("");
        }
        return "";
    }

    /**
     * Extract string value from an expression (handles arrays, strings, etc.).
     */
    private String extractStringValue(Expression expr) {
        if (expr instanceof StringLiteralExpr str) {
            return str.getValue();
        } else if (expr instanceof ArrayInitializerExpr array) {
            // Take first element for route
            return array.getValues().stream()
                    .findFirst()
                    .map(this::extractStringValue)
                    .orElse("");
        }
        return "";
    }

    /**
     * Extract HTTP methods from a mapping annotation.
     */
    private Set<HttpMethod> extractHttpMethods(MethodDeclaration method) {
        Set<HttpMethod> methods = EnumSet.noneOf(HttpMethod.class);

        for (AnnotationExpr annotation : method.getAnnotations()) {
            String name = annotation.getNameAsString();

            // Specific mapping annotations (GetMapping, PostMapping, etc.)
            if (ANNOTATION_TO_METHOD.containsKey(name)) {
                methods.add(ANNOTATION_TO_METHOD.get(name));
            }
            // @RequestMapping - check method attribute
            else if (name.equals("RequestMapping")) {
                methods.addAll(extractMethodsFromRequestMapping(annotation));
            }
        }

        // Default to GET if no methods specified
        if (methods.isEmpty()) {
            methods.add(HttpMethod.GET);
        }

        return methods;
    }

    /**
     * Extract HTTP methods from @RequestMapping annotation.
     */
    private Set<HttpMethod> extractMethodsFromRequestMapping(AnnotationExpr annotation) {
        Set<HttpMethod> methods = EnumSet.noneOf(HttpMethod.class);

        if (annotation instanceof NormalAnnotationExpr normal) {
            normal.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("method"))
                    .findFirst()
                    .ifPresent(pair -> {
                        Expression value = pair.getValue();
                        if (value instanceof ArrayInitializerExpr array) {
                            array.getValues().forEach(v -> extractMethodFromExpression(v, methods));
                        } else {
                            extractMethodFromExpression(value, methods);
                        }
                    });
        }

        return methods;
    }

    /**
     * Extract HTTP method from a field access expression (e.g., RequestMethod.GET).
     */
    private void extractMethodFromExpression(Expression expr, Set<HttpMethod> methods) {
        if (expr instanceof FieldAccessExpr field) {
            String methodName = field.getNameAsString();
            try {
                methods.add(HttpMethod.valueOf(methodName));
            } catch (IllegalArgumentException ignored) {
            }
        } else if (expr instanceof NameExpr name) {
            // Handle imported static constant
            try {
                methods.add(HttpMethod.valueOf(name.getNameAsString()));
            } catch (IllegalArgumentException ignored) {
            }
        }
    }

    /**
     * Create an endpoint from a controller method.
     */
    private Endpoint createEndpoint(ClassOrInterfaceDeclaration controller,
                                    MethodDeclaration method,
                                    String controllerName,
                                    String basePath,
                                    AuthorizationInfo classAuth,
                                    String filePath) {
        String methodPath = extractRequestMappingPath(method);
        String route = buildRoute(basePath, methodPath);
        Set<HttpMethod> httpMethods = extractHttpMethods(method);

        // Get method-level authorization and merge with class-level
        AuthorizationInfo methodAuth = authExtractor.extract(method);
        AuthorizationInfo mergedAuth = classAuth.mergeWith(methodAuth);

        int lineNumber = method.getBegin()
                .map(pos -> pos.line)
                .orElse(0);

        return Endpoint.builder()
                .route(route)
                .methods(httpMethods)
                .type(EndpointType.CONTROLLER)
                .controllerName(controllerName)
                .methodName(method.getNameAsString())
                .location(new SourceLocation(filePath, lineNumber))
                .authorization(mergedAuth)
                .build();
    }

    /**
     * Build the full route from base path and method path.
     */
    private String buildRoute(String basePath, String methodPath) {
        String base = normalizePath(basePath);
        String method = normalizePath(methodPath);

        if (base.isEmpty() && method.isEmpty()) {
            return "/";
        }
        if (base.isEmpty()) {
            return "/" + method;
        }
        if (method.isEmpty()) {
            return "/" + base;
        }
        return "/" + base + "/" + method;
    }

    /**
     * Normalize a path by removing leading/trailing slashes.
     */
    private String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.trim();
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
