package com.mastercard.developer.oauth2.internal.jose;

import com.mastercard.developer.oauth2.internal.json.JsonProvider;
import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a JSON Web Token with header and payload sections.
 */
public final class Jwt {

    private final Map<String, Object> header = new ConcurrentHashMap<>();
    private final Map<String, Object> payload = new ConcurrentHashMap<>();
    private String signature;

    /**
     * Adds a parameter to the JWT header.
     * If the value is null, the parameter is removed.
     */
    public void addHeaderParam(String key, Object value) {
        if (value == null) {
            header.remove(key);
            return;
        }
        header.put(key, value);
    }

    /**
     * Adds a claim to the JWT payload.
     * If the value is null, the claim is removed.
     */
    public void addClaim(String key, Object value) {
        if (value == null) {
            payload.remove(key);
            return;
        }
        payload.put(key, value);
    }

    /**
     * Generates the signing input for the JWT (base64url-encoded header and payload separated by a dot).
     */
    public String getSigningInput() throws OAuth2ClientJsonException {
        var jsonProvider = JsonProvider.getInstance();
        String headerJson = jsonProvider.write(header);
        String payloadJson = jsonProvider.write(payload);
        return "%s.%s".formatted(
            Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)),
            Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8))
        );
    }

    /**
     * Sets the signature for the JWT. The signature should be base64url-encoded.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Returns the complete JWT in JWS compact serialization format.
     */
    public String getSerialized() throws OAuth2ClientJsonException {
        if (signature == null) {
            throw new IllegalStateException("Signature is required");
        }
        return "%s.%s".formatted(getSigningInput(), signature);
    }
}
