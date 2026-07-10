package com.mastercard.developer.oauth2.core.access_token;

import java.util.Optional;
import java.util.Set;

/**
 * Filter criteria for retrieving access tokens from the token store.
 * When specified, all criteria must match ("AND" logic).
 */
public record AccessTokenFilter(Optional<String> jkt, Set<String> scopes) {
    /**
     * Creates a new filter with the specified criteria.
     */
    public AccessTokenFilter {
        scopes = null == scopes ? Set.of() : Set.copyOf(scopes);
    }

    /**
     * Creates a filter for the specified scopes.
     */
    public static AccessTokenFilter byScopes(Set<String> scopes) {
        return new AccessTokenFilter(Optional.empty(), scopes);
    }

    /**
     * Creates a filter for the specified JKT and scopes.
     */
    public static AccessTokenFilter byJktAndScopes(String jkt, Set<String> scopes) {
        return new AccessTokenFilter(Optional.of(jkt), scopes);
    }
}
