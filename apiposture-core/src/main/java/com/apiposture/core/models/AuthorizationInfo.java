package com.apiposture.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Authorization information extracted from Spring Security annotations.
 */
public final class AuthorizationInfo {

    @JsonProperty("hasAuthorize")
    private final boolean hasAuthorize;

    @JsonProperty("hasPermitAll")
    private final boolean hasPermitAll;

    @JsonProperty("hasDenyAll")
    private final boolean hasDenyAll;

    @JsonProperty("isAuthenticated")
    private final boolean isAuthenticated;

    @JsonProperty("roles")
    private final Set<String> roles;

    @JsonProperty("authorities")
    private final Set<String> authorities;

    @JsonProperty("preAuthorizeExpression")
    private final String preAuthorizeExpression;

    @JsonProperty("inheritedFrom")
    private final String inheritedFrom;

    private AuthorizationInfo(Builder builder) {
        this.hasAuthorize = builder.hasAuthorize;
        this.hasPermitAll = builder.hasPermitAll;
        this.hasDenyAll = builder.hasDenyAll;
        this.isAuthenticated = builder.isAuthenticated;
        this.roles = Collections.unmodifiableSet(new HashSet<>(builder.roles));
        this.authorities = Collections.unmodifiableSet(new HashSet<>(builder.authorities));
        this.preAuthorizeExpression = builder.preAuthorizeExpression;
        this.inheritedFrom = builder.inheritedFrom;
    }

    public boolean hasAuthorize() {
        return hasAuthorize;
    }

    public boolean hasPermitAll() {
        return hasPermitAll;
    }

    public boolean hasDenyAll() {
        return hasDenyAll;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public String getPreAuthorizeExpression() {
        return preAuthorizeExpression;
    }

    public String getInheritedFrom() {
        return inheritedFrom;
    }

    /**
     * Check if this authorization info has any form of security requirement.
     */
    public boolean hasAnySecurity() {
        return hasAuthorize || hasDenyAll || isAuthenticated || !roles.isEmpty() || !authorities.isEmpty();
    }

    /**
     * Check if this authorization info explicitly allows public access.
     */
    public boolean isExplicitlyPublic() {
        return hasPermitAll;
    }

    /**
     * Check if this authorization info is inherited from a class-level annotation.
     */
    public boolean isInherited() {
        return inheritedFrom != null && !inheritedFrom.isBlank();
    }

    /**
     * Create empty authorization info (no security).
     */
    public static AuthorizationInfo empty() {
        return builder().build();
    }

    /**
     * Create new builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create builder from existing instance.
     */
    public Builder toBuilder() {
        return new Builder()
                .hasAuthorize(this.hasAuthorize)
                .hasPermitAll(this.hasPermitAll)
                .hasDenyAll(this.hasDenyAll)
                .isAuthenticated(this.isAuthenticated)
                .roles(this.roles)
                .authorities(this.authorities)
                .preAuthorizeExpression(this.preAuthorizeExpression)
                .inheritedFrom(this.inheritedFrom);
    }

    /**
     * Merge this authorization info with another, with method-level taking precedence.
     */
    public AuthorizationInfo mergeWith(AuthorizationInfo methodLevel) {
        if (methodLevel == null) {
            return this;
        }

        // Method-level @PermitAll or @DenyAll completely overrides class-level
        if (methodLevel.hasPermitAll || methodLevel.hasDenyAll) {
            return methodLevel;
        }

        // If method has its own authorization, it overrides class
        if (methodLevel.hasAnySecurity()) {
            return methodLevel;
        }

        // Otherwise, inherit from class with note about inheritance
        if (this.hasAnySecurity()) {
            return this.toBuilder()
                    .inheritedFrom("class")
                    .build();
        }

        return methodLevel;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationInfo that = (AuthorizationInfo) o;
        return hasAuthorize == that.hasAuthorize &&
                hasPermitAll == that.hasPermitAll &&
                hasDenyAll == that.hasDenyAll &&
                isAuthenticated == that.isAuthenticated &&
                Objects.equals(roles, that.roles) &&
                Objects.equals(authorities, that.authorities) &&
                Objects.equals(preAuthorizeExpression, that.preAuthorizeExpression) &&
                Objects.equals(inheritedFrom, that.inheritedFrom);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hasAuthorize, hasPermitAll, hasDenyAll, isAuthenticated,
                roles, authorities, preAuthorizeExpression, inheritedFrom);
    }

    @Override
    public String toString() {
        return "AuthorizationInfo{" +
                "hasAuthorize=" + hasAuthorize +
                ", hasPermitAll=" + hasPermitAll +
                ", hasDenyAll=" + hasDenyAll +
                ", isAuthenticated=" + isAuthenticated +
                ", roles=" + roles +
                ", authorities=" + authorities +
                ", preAuthorizeExpression='" + preAuthorizeExpression + '\'' +
                ", inheritedFrom='" + inheritedFrom + '\'' +
                '}';
    }

    /**
     * Builder for AuthorizationInfo.
     */
    public static class Builder {
        private boolean hasAuthorize;
        private boolean hasPermitAll;
        private boolean hasDenyAll;
        private boolean isAuthenticated;
        private Set<String> roles = new HashSet<>();
        private Set<String> authorities = new HashSet<>();
        private String preAuthorizeExpression;
        private String inheritedFrom;

        public Builder hasAuthorize(boolean hasAuthorize) {
            this.hasAuthorize = hasAuthorize;
            return this;
        }

        public Builder hasPermitAll(boolean hasPermitAll) {
            this.hasPermitAll = hasPermitAll;
            return this;
        }

        public Builder hasDenyAll(boolean hasDenyAll) {
            this.hasDenyAll = hasDenyAll;
            return this;
        }

        public Builder isAuthenticated(boolean isAuthenticated) {
            this.isAuthenticated = isAuthenticated;
            return this;
        }

        public Builder roles(Set<String> roles) {
            this.roles = new HashSet<>(roles);
            return this;
        }

        public Builder addRole(String role) {
            this.roles.add(role);
            return this;
        }

        public Builder authorities(Set<String> authorities) {
            this.authorities = new HashSet<>(authorities);
            return this;
        }

        public Builder addAuthority(String authority) {
            this.authorities.add(authority);
            return this;
        }

        public Builder preAuthorizeExpression(String expression) {
            this.preAuthorizeExpression = expression;
            return this;
        }

        public Builder inheritedFrom(String inheritedFrom) {
            this.inheritedFrom = inheritedFrom;
            return this;
        }

        public AuthorizationInfo build() {
            return new AuthorizationInfo(this);
        }
    }
}
