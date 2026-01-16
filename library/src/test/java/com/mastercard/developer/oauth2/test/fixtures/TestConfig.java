package com.mastercard.developer.oauth2.test.fixtures;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.config.SecurityProfile;
import com.mastercard.developer.oauth2.core.dpop.StaticDPoPKeyProvider;
import com.mastercard.developer.oauth2.core.scope.ScopeResolver;
import com.mastercard.developer.oauth2.core.scope.StaticScopeResolver;
import com.mastercard.developer.oauth2.keys.KeyLoader;
import com.mastercard.developer.oauth2.test.mocks.FakeAuthorizationServer;
import com.mastercard.developer.oauth2.test.mocks.FakeResourceServer;
import io.github.cdimascio.dotenv.Dotenv;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Configuration for integration tests.
 */
public class TestConfig {

    /**
     * Loads environment variables from a .env file located in the root directory.
     */
    private static final Dotenv dotenv = Dotenv.configure().directory("..").ignoreIfMissing().load();

    private final OAuth2Config oauth2Config;
    private final String createResourceUri;
    private final String deleteResourceUri;
    private final String resourceJson;
    private final String apiBaseUrl;

    private TestConfig(OAuth2Config oauth2Config, String createResourceUri, String deleteResourceUri, String resourceJson, String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
        this.oauth2Config = oauth2Config;
        this.createResourceUri = createResourceUri;
        this.deleteResourceUri = deleteResourceUri;
        this.resourceJson = resourceJson;
    }

    public static TestConfig getMastercardApiConfig(KeyPair dpopKeyPair) throws Exception {
        String privateKeyContent = getEnv("PRIVATE_KEY");
        String clientId = getEnv("CLIENT_ID");
        String kid = getEnv("KID");
        String tokenEndpoint = getEnv("TOKEN_ENDPOINT");
        String issuer = getEnv("ISSUER");
        String apiBaseUrlEnv = getEnv("API_BASE_URL");
        String readScopes = getEnv("READ_SCOPES");
        String writeScopes = getEnv("WRITE_SCOPES");

        try {
            validateEnvVariable("PRIVATE_KEY", privateKeyContent);
            validateEnvVariable("CLIENT_ID", clientId);
            validateEnvVariable("KID", kid);
            validateEnvVariable("TOKEN_ENDPOINT", tokenEndpoint);
            validateEnvVariable("ISSUER", issuer);
            validateEnvVariable("API_BASE_URL", apiBaseUrlEnv);
            validateEnvVariable("READ_SCOPES", readScopes);
            validateEnvVariable("WRITE_SCOPES", readScopes);
        } catch (Exception e) {
            // Disable the calling test when environment variables are missing
            assumeTrue(false, "Test disabled: %s".formatted(e.getMessage()));
        }

        OAuth2Config oauth2Config = OAuth2Config.builder()
            .securityProfile(SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP)
            .clientId(clientId)
            .tokenEndpoint(URI.create(tokenEndpoint).toURL())
            .issuer(URI.create(issuer).toURL())
            .clientKey(KeyLoader.loadPrivateKey(new ByteArrayInputStream(privateKeyContent.getBytes())))
            .kid(kid)
            .scopeResolver(new TestScopeResolver(writeScopes, readScopes))
            .dpopKeyProvider(new StaticDPoPKeyProvider(dpopKeyPair))
            .build();

        String createResourceUri = String.format("%s/dogs", apiBaseUrlEnv);
        String deleteResourceUri = String.format("%s/pets", apiBaseUrlEnv);
        var resourceRepresentation = "{\"status\":{\"value\":\"AVAILABLE\"},\"name\":\"Buddy\",\"breed\":\"Golden Retriever\",\"color\":\"Golden\",\"gender\":\"MALE\"}";
        return new TestConfig(oauth2Config, createResourceUri, deleteResourceUri, resourceRepresentation, apiBaseUrlEnv);
    }

    public static TestConfig getFakeApiConfig(FakeAuthorizationServer authorizationServer, FakeResourceServer resourceServer, KeyPair dpopKeyPair) throws Exception {
        var tokenEndpoint = URI.create(authorizationServer.baseUrl() + "/oauth/token");
        var issuer = URI.create(authorizationServer.baseUrl());
        OAuth2Config oauth2Config = OAuth2Config.builder()
            .securityProfile(SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP)
            .clientId("fake_service_client_id")
            .tokenEndpoint(tokenEndpoint.toURL())
            .issuer(issuer.toURL())
            .clientKey(StaticKeys.RSA_KEY_PAIR.getPrivate())
            .kid("fake_service_kid")
            .scopeResolver(new StaticScopeResolver(Set.of("fake_service:full_access")))
            .dpopKeyProvider(new StaticDPoPKeyProvider(dpopKeyPair))
            .build();
        String apiBaseUrl = resourceServer.baseUrl();
        String resourceUri = String.format("%s/api/resources", apiBaseUrl);
        return new TestConfig(oauth2Config, resourceUri, resourceUri, "{}", apiBaseUrl);
    }

    public static TestConfig getMastercardApiConfig() throws Exception {
        return getMastercardApiConfig(StaticKeys.EC_KEY_PAIR);
    }

    public static TestConfig getFakeApiConfig(FakeAuthorizationServer authorizationServer, FakeResourceServer resourceServer) throws Exception {
        return getFakeApiConfig(authorizationServer, resourceServer, StaticKeys.EC_KEY_PAIR);
    }

    public OAuth2Config getOAuth2Config() {
        return oauth2Config;
    }

    public String getCreateResourceUri() {
        return createResourceUri;
    }

    public String getFetchResourceUri(String resourceId) {
        return String.format("%s/%s", createResourceUri, resourceId);
    }

    public String getDeleteResourceUri(String resourceId) {
        return String.format("%s/%s", deleteResourceUri, resourceId);
    }

    public String getResourceJson() {
        return resourceJson;
    }

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    /**
     * Gets environment variable value, checking both .env file and system environment.
     * System environment variables take precedence over .env file.
     */
    private static String getEnv(String key) {
        String systemValue = System.getenv(key);
        return systemValue != null ? systemValue : dotenv.get(key);
    }

    /**
     * Validates that an environment variable is set and not empty.
     */
    private static void validateEnvVariable(String name, String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException(
                String.format(
                    "Environment variable '%s' is missing.%n%n" +
                        "To run tests against the Mastercard service:%n" +
                        "1. Copy .env.example to .env in the project root%n" +
                        "2. Fill in all required values in .env%n" +
                        "3. See README.md for more details%n%n" +
                        "Required variables: CLIENT_ID, KID, TOKEN_ENDPOINT, ISSUER, API_BASE_URL, READ_SCOPES, WRITE_SCOPES, PRIVATE_KEY.",
                    name
                )
            );
        }
    }

    private static class TestScopeResolver implements ScopeResolver {

        final Set<String> write;
        final Set<String> read;

        public TestScopeResolver(String writeScopes, String readScopes) {
            write = Set.of(writeScopes.split(","));
            read = Set.of(readScopes.split(","));
        }

        @Override
        public Set<String> resolve(String httpMethod, URL url) {
            switch (httpMethod) {
                case "POST", "DELETE" -> {
                    return write;
                }
                case "GET" -> {
                    return read;
                }
                default -> throw new IllegalStateException("Unexpected method value: " + httpMethod);
            }
        }

        @Override
        public Set<String> allScopes() {
            return Stream.concat(write.stream(), read.stream()).collect(Collectors.toUnmodifiableSet());
        }
    }
}
