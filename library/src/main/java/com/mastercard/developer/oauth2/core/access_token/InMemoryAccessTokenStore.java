package com.mastercard.developer.oauth2.core.access_token;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link AccessTokenStore}.
 * This implementation uses a {@link ConcurrentHashMap} to store tokens and automatically
 * removes expired tokens during put operations. Tokens are indexed by a combination
 * of their JKT and sorted scopes to ensure consistent lookups.
 */
public final class InMemoryAccessTokenStore implements AccessTokenStore {

    private static final Duration expirationThreshold = Duration.ofSeconds(60);
    private final ConcurrentHashMap<String, AccessToken> store = new ConcurrentHashMap<>();

    @Override
    public void put(AccessToken accessToken) {
        removeExpiredTokens();
        String scopeOnlyKey = createKey(null, accessToken.scopes());
        store.put(scopeOnlyKey, accessToken);
        if (accessToken.jkt() != null) {
            String jktScopeKey = createKey(accessToken.jkt(), accessToken.scopes());
            store.put(jktScopeKey, accessToken);
        }
    }

    @Override
    public Optional<AccessToken> get(AccessTokenFilter filter) {
        String key = createKey(filter.jkt().orElse(null), filter.scopes());
        var threshold = Instant.now().plus(expirationThreshold);
        AccessToken accessToken = store.computeIfPresent(key, (k, existing) -> existing.expiresAt().isBefore(threshold) ? null : existing);
        return Optional.ofNullable(accessToken);
    }

    /**
     * Creates a normalized cache key from a JKT and scopes.
     * Scopes are sorted alphabetically to ensure consistent key generation
     * regardless of the order in which scopes are provided.
     */
    private static String createKey(String jkt, Set<String> scopes) {
        var sorted = new ArrayList<>(scopes);
        Collections.sort(sorted);
        var normalizedScopes = String.join(" ", sorted);
        return String.format("%s|%s", jkt != null ? jkt : "<none>", normalizedScopes);
    }

    /**
     * Removes all expired tokens from the store.
     * This method is called during put operations to prevent unbounded memory growth.
     */
    private void removeExpiredTokens() {
        var now = Instant.now();
        store.entrySet().removeIf(entry -> {
            AccessToken accessToken = entry.getValue();
            return accessToken == null || accessToken.expiresAt().isBefore(now);
        });
    }
}
