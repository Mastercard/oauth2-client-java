package com.mastercard.developer.oauth2.core;

import static com.mastercard.developer.oauth2.core.OAuth2Handler.AccessTokenResponse;
import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static java.net.http.HttpRequest.*;
import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.http.UserAgent;
import com.mastercard.developer.oauth2.test.fixtures.BaseClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Supplier;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test an OAuth 2.0–authenticated API request using the Java 11 HttpClient and {@link OAuth2Handler} utility/static methods.
 */
class OAuth2HandlerEndToEndTest extends BaseClientTest {

    private static HttpClient httpClient;

    @BeforeEach
    void setUp() {
        httpClient = HttpClient.newBuilder().build();
    }

    @ParameterizedTest
    @MethodSource("serverAndKeyProvider")
    void callSequence_ShouldSucceed(Supplier<TestConfig> configSupplier) throws Exception {
        // GIVEN
        TestConfig testConfig = configSupplier.get();

        // WHEN / THEN
        String accessToken = requestToken(testConfig);
        callApi(testConfig, accessToken);
    }

    private String requestToken(TestConfig config) throws Exception {
        OAuth2Config oauth2Config = config.getOAuth2Config();
        String dpoPKeyId = oauth2Config.getDPoPKeyProvider().getCurrentKey().getKeyId();
        URL tokenEndpoint = oauth2Config.getTokenEndpoint();
        String clientId = oauth2Config.getClientId();
        var scope = String.join(" ", oauth2Config.getScopeResolver().allScopes());
        String nonce;
        HttpResponse<String> response;

        String clientAssertion = OAuth2Handler.createClientAssertion(oauth2Config);

        // First attempt: DPoP without nonce
        String dpopNoNonce = OAuth2Handler.createTokenRequestDPoP(oauth2Config, dpoPKeyId, null);
        response = sendTokenRequest(tokenEndpoint, clientId, scope, clientAssertion, dpopNoNonce);
        assertEquals(400, response.statusCode());
        nonce = response.headers().firstValue(DPOP_NONCE.value()).orElse(null);
        assertNotNull(nonce);

        // Second attempt: DPoP with nonce
        String dpopWithNonce = OAuth2Handler.createTokenRequestDPoP(oauth2Config, dpoPKeyId, nonce);
        response = sendTokenRequest(tokenEndpoint, clientId, scope, clientAssertion, dpopWithNonce);
        assertEquals(200, response.statusCode());
        assertNotNull(response.body());
        AccessTokenResponse accessToken = OAuth2Handler.parseAccessTokenJson(response.body());
        return accessToken.tokenValue();
    }

    private void callApi(TestConfig config, String accessToken) throws Exception {
        OAuth2Config oauth2Config = config.getOAuth2Config();
        String dpoPKeyId = oauth2Config.getDPoPKeyProvider().getCurrentKey().getKeyId();
        String resourceUri = config.getCreateResourceUri();
        String resourceJson = config.getResourceJson();
        String nonce;
        HttpResponse<String> response;

        // First attempt: DPoP with the wrong nonce
        String dpopWrongNonce = OAuth2Handler.createResourceRequestDPoP(oauth2Config, dpoPKeyId, "POST", resourceUri, accessToken, "some_nonce");
        Builder builder = HttpRequest.newBuilder()
            .header(ACCEPT.value(), "application/json")
            .header(CONTENT_TYPE.value(), "application/json")
            .header(AUTHORIZATION.value(), "DPoP " + accessToken)
            .header(DPOP.value(), dpopWrongNonce);
        response = sendPostRequest(URI.create(resourceUri).toURL(), resourceJson, builder);
        assertEquals(401, response.statusCode());
        assertNotNull(response.headers().firstValue(WWW_AUTHENTICATE.value()).orElse(null));
        nonce = response.headers().firstValue(DPOP_NONCE.value()).orElse(null);
        assertNotNull(nonce);

        // Second attempt: DPoP with nonce
        String dpopWithNonce = OAuth2Handler.createResourceRequestDPoP(oauth2Config, dpoPKeyId, "POST", resourceUri, accessToken, nonce);
        builder.setHeader(DPOP.value(), dpopWithNonce);
        response = sendPostRequest(URI.create(resourceUri).toURL(), resourceJson, builder);
        assertEquals(200, response.statusCode());
        assertNotNull(response.body());
        assertTrue(response.body().contains("id")); // Resource created
    }

    private static HttpResponse<String> sendTokenRequest(URL tokenEndpoint, String clientId, String scope, String clientAssertion, String dpopProof) throws Exception {
        String body = OAuth2Handler.createAccessTokenRequestBody(clientId, scope, clientAssertion);
        Builder builder = HttpRequest.newBuilder()
            .header(CONTENT_TYPE.value(), "application/x-www-form-urlencoded")
            .header(ACCEPT.value(), "application/json")
            .header(DPOP.value(), dpopProof);
        return sendPostRequest(tokenEndpoint, body, builder);
    }

    private static HttpResponse<String> sendPostRequest(URL url, String payload, Builder requestBuilder) throws Exception {
        HttpRequest request = requestBuilder.setHeader(USER_AGENT.value(), UserAgent.get()).uri(url.toURI()).POST(BodyPublishers.ofString(payload)).build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
