package com.mastercard.developer.oauth2.core.access_token;

import java.util.Optional;

/**
 * Interface for caching and retrieving OAuth 2.0 access tokens.
 * Implementations should handle token expiration and provide thread-safe operations.
 */
public sealed interface AccessTokenStore  permits InMemoryAccessTokenStore {
    /**
     * Adds an access token to the store.
     */
    void put(AccessToken accessToken);

    /**
     * Retrieves an access token matching the specified filter criteria ("AND" logic).
     * Returns an empty {@link Optional} if no token was found, or if the stored token has expired.
     */
    Optional<AccessToken> get(AccessTokenFilter filter);
}
