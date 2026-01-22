package com.apiposture.core.authorization;

import com.apiposture.core.models.AuthorizationInfo;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts authorization information from Spring Security annotations.
 * Supports: @PreAuthorize, @Secured, @RolesAllowed, @PermitAll, @DenyAll
 */
public class AnnotationAuthorizationExtractor {

    // Pattern to extract roles from hasRole('ROLE')
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile(
            "hasRole\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern to extract authorities from hasAuthority('AUTH')
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile(
            "hasAuthority\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern to extract from hasAnyRole('A', 'B')
    private static final Pattern HAS_ANY_ROLE_PATTERN = Pattern.compile(
            "hasAnyRole\\s*\\(([^)]+)\\)",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern to extract from hasAnyAuthority('A', 'B')
    private static final Pattern HAS_ANY_AUTHORITY_PATTERN = Pattern.compile(
            "hasAnyAuthority\\s*\\(([^)]+)\\)",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern to detect isAuthenticated()
    private static final Pattern IS_AUTHENTICATED_PATTERN = Pattern.compile(
            "isAuthenticated\\s*\\(\\s*\\)",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern to extract quoted strings
    private static final Pattern QUOTED_STRING_PATTERN = Pattern.compile(
            "['\"]([^'\"]+)['\"]"
    );

    /**
     * Extract authorization info from an annotated node (class or method).
     */
    public AuthorizationInfo extract(NodeWithAnnotations<?> node) {
        AuthorizationInfo.Builder builder = AuthorizationInfo.builder();
        Set<String> roles = new HashSet<>();
        Set<String> authorities = new HashSet<>();

        for (AnnotationExpr annotation : node.getAnnotations()) {
            String name = annotation.getNameAsString();

            switch (name) {
                case "PreAuthorize" -> {
                    builder.hasAuthorize(true);
                    String expression = extractAnnotationValue(annotation);
                    builder.preAuthorizeExpression(expression);
                    parsePreAuthorizeExpression(expression, roles, authorities, builder);
                }
                case "Secured" -> {
                    builder.hasAuthorize(true);
                    extractSecuredRoles(annotation, roles);
                }
                case "RolesAllowed" -> {
                    builder.hasAuthorize(true);
                    extractRolesAllowed(annotation, roles);
                }
                case "PermitAll" -> builder.hasPermitAll(true);
                case "DenyAll" -> builder.hasDenyAll(true);
            }
        }

        builder.roles(roles);
        builder.authorities(authorities);

        return builder.build();
    }

    /**
     * Extract the value from an annotation.
     */
    private String extractAnnotationValue(AnnotationExpr annotation) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            return extractStringFromExpression(single.getMemberValue());
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            return normal.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("value"))
                    .findFirst()
                    .map(p -> extractStringFromExpression(p.getValue()))
                    .orElse("");
        }
        return "";
    }

    /**
     * Extract string value from an expression.
     */
    private String extractStringFromExpression(Expression expr) {
        if (expr instanceof StringLiteralExpr str) {
            return str.getValue();
        }
        return expr.toString();
    }

    /**
     * Parse @PreAuthorize expression and extract roles/authorities.
     */
    private void parsePreAuthorizeExpression(String expression, Set<String> roles,
                                             Set<String> authorities,
                                             AuthorizationInfo.Builder builder) {
        if (expression == null || expression.isBlank()) {
            return;
        }

        // Check for isAuthenticated()
        if (IS_AUTHENTICATED_PATTERN.matcher(expression).find()) {
            builder.isAuthenticated(true);
        }

        // Extract hasRole
        Matcher hasRoleMatcher = HAS_ROLE_PATTERN.matcher(expression);
        while (hasRoleMatcher.find()) {
            String role = normalizeRole(hasRoleMatcher.group(1));
            roles.add(role);
        }

        // Extract hasAnyRole
        Matcher hasAnyRoleMatcher = HAS_ANY_ROLE_PATTERN.matcher(expression);
        while (hasAnyRoleMatcher.find()) {
            String rolesStr = hasAnyRoleMatcher.group(1);
            extractQuotedStrings(rolesStr).forEach(r -> roles.add(normalizeRole(r)));
        }

        // Extract hasAuthority
        Matcher hasAuthorityMatcher = HAS_AUTHORITY_PATTERN.matcher(expression);
        while (hasAuthorityMatcher.find()) {
            authorities.add(hasAuthorityMatcher.group(1));
        }

        // Extract hasAnyAuthority
        Matcher hasAnyAuthorityMatcher = HAS_ANY_AUTHORITY_PATTERN.matcher(expression);
        while (hasAnyAuthorityMatcher.find()) {
            String authStr = hasAnyAuthorityMatcher.group(1);
            authorities.addAll(extractQuotedStrings(authStr));
        }
    }

    /**
     * Extract roles from @Secured annotation.
     */
    private void extractSecuredRoles(AnnotationExpr annotation, Set<String> roles) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            extractRolesFromExpression(single.getMemberValue(), roles);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            normal.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("value"))
                    .findFirst()
                    .ifPresent(p -> extractRolesFromExpression(p.getValue(), roles));
        }
    }

    /**
     * Extract roles from @RolesAllowed annotation.
     */
    private void extractRolesAllowed(AnnotationExpr annotation, Set<String> roles) {
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            extractRolesFromExpression(single.getMemberValue(), roles);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            normal.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("value"))
                    .findFirst()
                    .ifPresent(p -> extractRolesFromExpression(p.getValue(), roles));
        }
    }

    /**
     * Extract role strings from an expression (string or array).
     */
    private void extractRolesFromExpression(Expression expr, Set<String> roles) {
        if (expr instanceof StringLiteralExpr str) {
            roles.add(normalizeRole(str.getValue()));
        } else if (expr instanceof ArrayInitializerExpr array) {
            array.getValues().forEach(v -> {
                if (v instanceof StringLiteralExpr str) {
                    roles.add(normalizeRole(str.getValue()));
                }
            });
        }
    }

    /**
     * Normalize a role by removing ROLE_ prefix if present.
     */
    private String normalizeRole(String role) {
        if (role == null) {
            return "";
        }
        // Don't remove ROLE_ prefix - keep original to preserve Spring's convention
        return role.trim();
    }

    /**
     * Extract quoted strings from a comma-separated list.
     */
    private Set<String> extractQuotedStrings(String input) {
        Set<String> strings = new HashSet<>();
        Matcher matcher = QUOTED_STRING_PATTERN.matcher(input);
        while (matcher.find()) {
            strings.add(matcher.group(1));
        }
        return strings;
    }
}
