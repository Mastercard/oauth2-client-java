package com.mastercard.developer.oauth2.core.dpop;

/**
 * DPoP key provider used to supply keys for creating DPoP proofs.
 */
public sealed interface DPoPKeyProvider permits StaticDPoPKeyProvider {
    /**
     * Gets the current key to be used for signing DPoP proofs.
     */
    DPoPKey getCurrentKey();

    /**
     * Returns a key by "kid" (useful in scenarios where the provider returns different key pairs over time).
     */
    DPoPKey getKey(String kid);
}
