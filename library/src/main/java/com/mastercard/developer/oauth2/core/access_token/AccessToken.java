package com.mastercard.developer.oauth2.core.access_token;

import java.time.Instant;
import java.util.Set;

/**
 * Immutable model for an access token and its metadata.
 *
 * @param clientId   the client ID associated with this access token
 * @param scopes     the set of scopes associated with this access token
 * @param expiresAt  the expiration time of the access token
 * @param jkt        an optional JWK thumbprint (jkt) associated with this access token (only for DPoP-bound tokens)
 * @param tokenValue the string value of the access token
 */
public record AccessToken(String clientId, Set<String> scopes, Instant expiresAt, String jkt, String tokenValue) {
    /**
     * Creates a new access token
     */
    public AccessToken {
        scopes = null == scopes ? Set.of() : Set.copyOf(scopes);
    }

    /**
     * Creates a new access token without DPoP binding.
     */
    public AccessToken(String clientId, Set<String> scopes, Instant expiresAt, String tokenValue) {
        this(clientId, scopes, expiresAt, null, tokenValue);
    }
}
