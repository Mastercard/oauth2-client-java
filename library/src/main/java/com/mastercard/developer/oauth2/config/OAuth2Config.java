package com.mastercard.developer.oauth2.config;

import com.mastercard.developer.oauth2.config.exception.OAuth2ClientConfigException;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenStore;
import com.mastercard.developer.oauth2.core.access_token.InMemoryAccessTokenStore;
import com.mastercard.developer.oauth2.core.dpop.DPoPKey;
import com.mastercard.developer.oauth2.core.dpop.DPoPKeyProvider;
import com.mastercard.developer.oauth2.core.scope.ScopeResolver;
import com.mastercard.developer.oauth2.http.UserAgent;
import java.net.URL;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Duration;

/**
 * Immutable configuration for OAuth2 clients supporting DPoP-bound access tokens.
 * This class provides all necessary configuration parameters for establishing OAuth2
 * authentication with token endpoint, including client credentials, DPoP proof generation,
 * scope management, and access token storage.
 * <p>
 * Configuration instances are created using the builder pattern. All required fields must
 * be provided before building, otherwise an {@link OAuth2ClientConfigException} will be thrown.
 * <p>
 * Example usage:
 * <pre>
 * OAuth2Config config = OAuth2Config.builder()
 *     .securityProfile(SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP)
 *     .clientId("ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry")
 *     .tokenEndpoint(URI.create("https://sandbox.api.mastercard.com/oauth/token"))
 *     .issuer(URI.create("https://sandbox.api.mastercard.com"))
 *     .clientKey(clientKey)
 *     .kid("302449525fad5309874b16298f3cbaaf0000000000000000")
 *     .accessTokenStore(new InMemoryAccessTokenStore())
 *     .scopeResolver(new StaticScopeResolver(Set.of("service:scope1", "service:scope2")))
 *     .dpopKeyProvider(new StaticDPoPKeyProvider(dpopKeyPair))
 *     .clockSkewTolerance(Duration.ofSeconds(10))
 *     .build();
 * </pre>
 */
public class OAuth2Config {

    private final String clientId;
    private final URL tokenEndpoint;
    private final URL issuer;
    private final Duration clockSkewTolerance;
    private final String userAgent;
    private final ScopeResolver scopeResolver;
    private final AccessTokenStore accessTokenStore;
    private final PrivateKey clientKey;
    private final String kid;
    private final DPoPKeyProvider dpopKeyProvider;
    private final SecurityProfile securityProfile;

    private OAuth2Config(OAuth2ConfigBuilder builder) {
        this.clientId = builder.clientId;
        this.tokenEndpoint = builder.tokenEndpoint;
        this.issuer = builder.issuer;
        this.clockSkewTolerance = builder.clockSkewTolerance;
        this.userAgent = builder.userAgent;
        this.scopeResolver = builder.scopeResolver;
        this.accessTokenStore = builder.accessTokenStore;
        this.clientKey = builder.clientKey;
        this.kid = builder.kid;
        this.dpopKeyProvider = builder.dpopKeyProvider;
        this.securityProfile = builder.securityProfile;
    }

    /**
     * Create a new builder for {@link OAuth2Config}.
     */
    public static OAuth2ConfigBuilder builder() {
        return new OAuth2ConfigBuilder();
    }

    public URL getIssuer() {
        return issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public URL getTokenEndpoint() {
        return tokenEndpoint;
    }

    public Duration getClockSkewTolerance() {
        return clockSkewTolerance;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public ScopeResolver getScopeResolver() {
        return scopeResolver;
    }

    public AccessTokenStore getAccessTokenStore() {
        return accessTokenStore;
    }

    public PrivateKey getClientKey() {
        return clientKey;
    }

    public String getKid() {
        return kid;
    }

    public DPoPKeyProvider getDPoPKeyProvider() {
        return dpopKeyProvider;
    }

    /**
     * Builder for constructing {@link OAuth2Config} instances.
     * Provides a fluent API for configuring all OAuth2 client parameters with validation
     * on build. Default values are provided for optional parameters.
     */
    public static class OAuth2ConfigBuilder {

        private String clientId;
        private URL tokenEndpoint;
        private URL issuer;
        private Duration clockSkewTolerance = Duration.ofSeconds(5);
        private String userAgent = UserAgent.get();
        private ScopeResolver scopeResolver;
        private AccessTokenStore accessTokenStore = new InMemoryAccessTokenStore();
        private PrivateKey clientKey;
        private String kid;
        private DPoPKeyProvider dpopKeyProvider;
        private SecurityProfile securityProfile = SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP;

        private OAuth2ConfigBuilder() {}

        /**
         * Sets the authorization server's unique identifier.
         * See: <a href="https://datatracker.ietf.org/doc/html/rfc8414#section-2">Authorization Server Metadata</a>
         */
        public OAuth2ConfigBuilder issuer(URL issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the OAuth2 client identifier.
         */
        public OAuth2ConfigBuilder clientId(String clientId) {
            this.clientId = clientId.trim();
            return this;
        }

        /**
         * Sets the OAuth2 token endpoint URL where token requests will be sent.
         */
        public OAuth2ConfigBuilder tokenEndpoint(URL tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
            return this;
        }

        /**
         * Sets the tolerance for clock skew when validating token expiration.
         * Must be a positive duration. Default is 5 seconds.
         */
        public OAuth2ConfigBuilder clockSkewTolerance(Duration tolerance) {
            if (tolerance == null || tolerance.isNegative()) {
                throw new OAuth2ClientConfigException("Clock skew tolerance must be positive");
            }
            this.clockSkewTolerance = tolerance;
            return this;
        }

        /**
         * Sets the resolver that determines which scopes to request for each API call.
         */
        public OAuth2ConfigBuilder scopeResolver(ScopeResolver resolver) {
            this.scopeResolver = resolver;
            return this;
        }

        /**
         * Sets the storage mechanism for caching access tokens.
         * Default is in-memory storage.
         */
        public OAuth2ConfigBuilder accessTokenStore(AccessTokenStore accessTokenStore) {
            this.accessTokenStore = accessTokenStore;
            return this;
        }

        /**
         * Sets the User-Agent header value for HTTP requests.
         * Default uses the library's generated user agent string.
         */
        public OAuth2ConfigBuilder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        /**
         * Sets the private key used for client authentication via private_key_jwt.
         */
        public OAuth2ConfigBuilder clientKey(PrivateKey clientKey) {
            this.clientKey = clientKey;
            return this;
        }

        /**
         * Sets the key identifier for the client authentication key.
         */
        public OAuth2ConfigBuilder kid(String kid) {
            this.kid = kid.trim();
            return this;
        }

        /**
         * Sets the provider for DPoP key pairs used to generate DPoP proof tokens.
         */
        public OAuth2ConfigBuilder dpopKeyProvider(DPoPKeyProvider dpopKeyProvider) {
            this.dpopKeyProvider = dpopKeyProvider;
            return this;
        }

        /**
         * Sets the OAuth 2 security profile to use.
         * Default is SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP.
         */
        public OAuth2ConfigBuilder securityProfile(SecurityProfile securityProfile) {
            this.securityProfile = securityProfile;
            return this;
        }

        /**
         * Builds the OAuth2Config instance.
         */
        public OAuth2Config build() {
            validate();
            return new OAuth2Config(this);
        }

        /**
         * Validates the configuration parameters match the security profile requirements.
         * For now, only FAPI 2.0 with private_key_jwt and DPoP is supported.
         */
        private void validate() {
            if (securityProfile == null) {
                throw new OAuth2ClientConfigException("Security profile is required");
            }
            if (securityProfile != SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP) {
                throw new OAuth2ClientConfigException("Security profile must be FAPI 2.0 with private_key_jwt and DPoP");
            }
            if (clientId == null || clientId.trim().isEmpty()) {
                throw new OAuth2ClientConfigException("Client ID is required");
            }
            if (tokenEndpoint == null) {
                throw new OAuth2ClientConfigException("Token endpoint is required");
            }
            if (issuer == null) {
                throw new OAuth2ClientConfigException("Issuer is required");
            }
            if (scopeResolver == null) {
                throw new OAuth2ClientConfigException("Scope resolver is required");
            }
            if (accessTokenStore == null) {
                throw new OAuth2ClientConfigException("Token store is required");
            }
            if (userAgent == null) {
                throw new OAuth2ClientConfigException("User agent is required");
            }
            if (clientKey == null) {
                throw new OAuth2ClientConfigException("Client private key is required");
            }
            if (kid == null || kid.trim().isEmpty()) {
                throw new OAuth2ClientConfigException("Key ID (kid) is required");
            }
            if (dpopKeyProvider == null) {
                throw new OAuth2ClientConfigException("DPoP key provider is required");
            }
            validateDPoPKey(dpopKeyProvider.getCurrentKey());
            validateKey(clientKey);
        }

        private void validateDPoPKey(DPoPKey dPoPKey) {
            if (dPoPKey == null || dPoPKey.getKeyPair() == null) {
                throw new OAuth2ClientConfigException("DPoP key provider must return a valid DPoP key");
            }
            if (dPoPKey.getKeyId() == null) {
                throw new OAuth2ClientConfigException("DPoP key provider must return a valid DPoP key ID");
            }
            validateKey(dPoPKey.getKeyPair().getPrivate());
            validateKey(dPoPKey.getKeyPair().getPublic());
        }

        /**
         * Validates that keys meet security requirements.
         * See: <a href="https://openid.bitbucket.io/fapi/fapi-security-profile-2_0.html#name-cryptography-and-secrets">5.4. Cryptography and secrets</a>
         */
        private void validateKey(Key key) {
            if (!(key instanceof RSAKey) && !(key instanceof ECKey)) {
                throw new OAuth2ClientConfigException("Key algorithm must be RSA or EC, but was: " + key.getAlgorithm());
            }
            if (key instanceof RSAKey rsaKey) {
                int keyLength = rsaKey.getModulus().bitLength();
                if (keyLength < 2048) {
                    throw new OAuth2ClientConfigException("RSA keys must have a minimum length of 2048 bits, but key length was: " + keyLength);
                }
            }

            if (key instanceof ECKey ecKey) {
                int keyLength = ecKey.getParams().getCurve().getField().getFieldSize();
                if (keyLength < 224) {
                    throw new OAuth2ClientConfigException("Elliptic curve keys must have a minimum length of 224 bits, but key length was: " + keyLength);
                }
            }
        }
    }

    @Override
    public String toString() {
        return """
        OAuth2Config {
          clientId='%s',
          tokenEndpoint='%s',
          issuer='%s',
          clockSkewTolerance='%s',
          userAgent='%s',
          accessTokenStore='%s',
          scopeResolver='%s',
          kid='%s',
          clientKey='%s',
          dpopKeyProvider='%s',
          securityProfile='%s'
        }""".formatted(
            clientId,
            tokenEndpoint,
            issuer,
            clockSkewTolerance,
            userAgent,
            formatName(accessTokenStore),
            formatName(scopeResolver),
            kid,
            formatPrivateKey(clientKey),
            formatName(dpopKeyProvider),
            securityProfile
        );
    }

    private static String formatPrivateKey(PrivateKey key) {
        return String.format("PrivateKey[class=%s, algorithm=%s, format=%s]", formatName(key), key.getAlgorithm(), key.getFormat());
    }

    private static String formatName(Object object) {
        var simpleName = object.getClass().getSimpleName();
        return !simpleName.isBlank() ? simpleName : object.getClass().getName();
    }
}
