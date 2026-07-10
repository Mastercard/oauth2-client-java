package com.mastercard.developer.oauth2.core;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.access_token.AccessToken;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenFilter;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenStore;
import com.mastercard.developer.oauth2.core.dpop.DPoPKeyProvider;
import com.mastercard.developer.oauth2.core.scope.ScopeResolver;
import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URL;
import java.util.HashSet;
import java.util.Optional;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.LoggerFactory;

/**
 * Tests for the {@link OAuth2Handler} execute method.
 */
@SuppressWarnings("OptionalGetWithoutIsPresent") // Simpler assertions
class OAuth2HandlerExecuteTest extends BaseTest {

    @Mock
    private HttpAdapter<String, String> adapter;

    @Mock
    private AccessTokenStore tokenStore;

    @Mock
    private DPoPKeyProvider dpopKeyProvider;

    @Mock
    private ScopeResolver scopeResolver;

    private String authorizationServerNonce;
    private String resourceServerNonce;
    private String requestObject;
    private String responseObject;
    private OAuth2Config config;
    private Logger logbackLogger;
    private ListAppender<ILoggingEvent> listAppender;
    private AutoCloseable mocksCloseable;

    @BeforeEach
    void setUp() throws Exception {
        mocksCloseable = MockitoAnnotations.openMocks(this);

        // Default HttpAdapter behavior
        // First call to the authorization server returns HTTP 400 use_dpop_nonce error. Second call to the authorization server returns a successful response.
        // First call to the resource server returns HTTP 401 use_dpop_nonce error. Second call to the resource server returns a successful response.
        authorizationServerNonce = "744cee0b7fe7830d2dc26d6f1901c53f";
        resourceServerNonce = "ec2808ba7410b17b04b4af962fd01732";
        requestObject = "test-request-object";
        responseObject = "test-response-object";
        var tokenResponseObject = "token-response-object";
        when(adapter.getUrl(requestObject)).thenReturn(URI.create(sampleResourceUrl).toURL());
        when(adapter.getMethod(requestObject)).thenReturn(sampleResourceMethod);
        when(adapter.sendAccessTokenRequest(eq(requestObject), eq(sampleTokenEndpoint), anyString(), any())).thenReturn(tokenResponseObject);
        when(adapter.readBody(tokenResponseObject))
            .thenReturn(
                Optional.of(
                    """
                    {
                        "error": "use_dpop_nonce"
                    }"""
                )
            )
            .thenReturn(Optional.of(sampleAccessTokenResponse));
        when(adapter.getStatusCode(tokenResponseObject)).thenReturn(400).thenReturn(200);
        when(adapter.getHeader(tokenResponseObject, DPOP_NONCE.value())).thenReturn(Optional.of(authorizationServerNonce)).thenReturn(Optional.empty());
        when(adapter.sendResourceRequest(eq(requestObject), any())).thenReturn(responseObject);
        when(adapter.readBody(responseObject)).thenReturn(Optional.empty()).thenReturn(Optional.of("{\"success\":\"true\"}"));
        when(adapter.getStatusCode(responseObject)).thenReturn(401).thenReturn(201);
        when(adapter.getHeader(responseObject, DPOP_NONCE.value())).thenReturn(Optional.of(resourceServerNonce)).thenReturn(Optional.empty());
        when(adapter.getHeader(responseObject, WWW_AUTHENTICATE.value()))
            .thenReturn(Optional.of("DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\""))
            .thenReturn(Optional.empty());

        // Default ScopeResolver behavior
        when(scopeResolver.resolve(sampleResourceMethod, URI.create(sampleResourceUrl).toURL())).thenReturn(sampleScopes);

        // Default AccessTokenStore behavior
        when(tokenStore.get(any(AccessTokenFilter.class))).thenReturn(Optional.empty());

        // Default DPoPKeyProvider behavior
        var dpopKey = sampleDpopKeyProvider.getCurrentKey();
        when(dpopKeyProvider.getCurrentKey()).thenReturn(dpopKey);
        when(dpopKeyProvider.getKey(sampleDpopKid)).thenReturn(dpopKey);

        // Default configuration
        config = sampleConfigBuilder.accessTokenStore(tokenStore).dpopKeyProvider(dpopKeyProvider).scopeResolver(scopeResolver).build();

        // Logger
        logbackLogger = (Logger) LoggerFactory.getLogger(OAuth2Handler.class);
        listAppender = new ListAppender<>();
        listAppender.start();
        logbackLogger.addAppender(listAppender);
    }

    @Test
    void execute_ShouldReuseAccessToken_WhenAccessTokenInStore() throws Exception {
        // GIVEN
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken);
        var filter = AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes);
        when(tokenStore.get(filter)).thenReturn(Optional.of(accessToken));

        // WHEN
        var handler = new OAuth2Handler(config);
        var response = handler.execute(requestObject, adapter);

        // THEN
        assertEquals(responseObject, response);
        verify(tokenStore).get(filter);
        verify(adapter, never()).sendAccessTokenRequest(any(), any(), any(), any());
        verify(adapter, times(2)).sendResourceRequest(eq(requestObject), any(HttpHeaders.class));
    }

    @Test
    void execute_ShouldReturnErrorResponse_WhenAuthorizationServerError() throws Exception {
        // GIVEN
        var errorResponseObject = "token-error-response";
        when(adapter.sendAccessTokenRequest(eq(requestObject), any(URL.class), anyString(), any(HttpHeaders.class))).thenReturn(errorResponseObject);
        when(adapter.getStatusCode(errorResponseObject)).thenReturn(500);
        when(adapter.readBody(errorResponseObject)).thenReturn(Optional.of("{\"error\":\"internal_error\"}"));

        // WHEN
        var handler = new OAuth2Handler(config);
        var response = handler.execute(requestObject, adapter);

        // THEN
        assertEquals(errorResponseObject, response);
        verify(adapter).sendAccessTokenRequest(eq(requestObject), any(URL.class), anyString(), any(HttpHeaders.class));
        verify(adapter, never()).sendResourceRequest(any(), any());
        assertEquals(
            "Access token request failed (HTTP 500), body: {\"error\":\"internal_error\"}",
            listAppender.list
                .stream()
                .filter(e -> e.getLevel() == Level.ERROR)
                .findFirst()
                .orElseThrow()
                .getFormattedMessage()
        );
    }

    @Test
    void execute_ShouldReturnErrorResponse_WhenResourceServerError() throws Exception {
        // GIVEN
        var errorResponseObject = "resource-error-response";
        when(adapter.sendResourceRequest(eq(requestObject), any(HttpHeaders.class))).thenReturn(errorResponseObject);
        when(adapter.getStatusCode(errorResponseObject)).thenReturn(500);
        when(adapter.readBody(errorResponseObject)).thenReturn(Optional.of("{\"error\":\"internal_error\"}"));

        // WHEN
        var handler = new OAuth2Handler(config);
        var response = handler.execute(requestObject, adapter);

        // THEN
        assertEquals(errorResponseObject, response);
        verify(adapter, times(2)).sendAccessTokenRequest(eq(requestObject), any(URL.class), anyString(), any(HttpHeaders.class));
        verify(adapter).sendResourceRequest(eq(requestObject), any(HttpHeaders.class));
        assertEquals(
            "API call failed (HTTP 500), body: {\"error\":\"internal_error\"}",
            listAppender.list
                .stream()
                .filter(e -> e.getLevel() == Level.ERROR)
                .findFirst()
                .orElseThrow()
                .getFormattedMessage()
        );
    }

    @Test
    @SuppressWarnings("java:S5961")
    void execute_ShouldExecuteEntireFlow() throws Exception {
        // WHEN
        var handler = new OAuth2Handler(config);
        var response = handler.execute(requestObject, adapter);

        // THEN
        assertEquals(responseObject, response);
        assertNotNull(
            listAppender.list
                .stream()
                .filter(e -> e.getLevel() == Level.DEBUG && "API call successful (HTTP 201), body: {\"success\":\"true\"}".equals(e.getFormattedMessage()))
                .findFirst()
        );

        // Verify authorization server was called, request headers and DPoP nonces
        var tokenRequestBodyCaptor = ArgumentCaptor.forClass(String.class);
        var tokenRequestHeadersCaptor = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(adapter, times(2)).sendAccessTokenRequest(eq(requestObject), eq(sampleTokenEndpoint), tokenRequestBodyCaptor.capture(), tokenRequestHeadersCaptor.capture());
        var tokenRequestHeaders = tokenRequestHeadersCaptor.getAllValues();
        verifyTokenRequestHeaders(tokenRequestHeaders.get(0), null);
        verifyTokenRequestHeaders(tokenRequestHeaders.get(1), authorizationServerNonce);

        // Verify the access token request form bodies
        tokenRequestBodyCaptor.getAllValues().forEach(body -> {
            assertTrue(body.contains("client_id=" + sampleClientId));
            assertTrue(body.contains("grant_type=client_credentials"));
            assertTrue(body.contains("scope=service%3Ascope1+service%3Ascope2"));
            assertTrue(body.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"));
            assertTrue(body.contains("client_assertion="));
        });

        // Verify client assertions are not reused across requests
        var clientAssertions = tokenRequestBodyCaptor.getAllValues().stream().map(OAuth2HandlerExecuteTest::extractClientAssertion).toList();
        var uniqueAssertions = new HashSet<>(clientAssertions);
        assertEquals(clientAssertions.size(), uniqueAssertions.size());

        // Verify resource server was called, request headers and DPoP nonces
        var resourceRequestHeadersCaptor = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(adapter, times(2)).sendResourceRequest(eq(requestObject), resourceRequestHeadersCaptor.capture());
        var resourceRequestHeaders = resourceRequestHeadersCaptor.getAllValues();
        verifyResourceRequestHeaders(resourceRequestHeaders.get(0), authorizationServerNonce);
        verifyResourceRequestHeaders(resourceRequestHeaders.get(1), resourceServerNonce);

        // Verify token store was called
        var filter = AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes);
        verify(tokenStore).get(filter);
        var accessTokenCaptor = ArgumentCaptor.forClass(AccessToken.class);
        verify(tokenStore).put(accessTokenCaptor.capture());
        var savedToken = accessTokenCaptor.getValue();
        assertEquals(sampleAccessToken, savedToken.tokenValue());
        assertEquals(sampleScopes, savedToken.scopes());

        // Verify scope resolver was called
        verify(scopeResolver).resolve(sampleResourceMethod, URI.create(sampleResourceUrl).toURL());

        // Verify DPoP key provider was called
        verify(dpopKeyProvider, times(2)).getCurrentKey();
        verify(dpopKeyProvider, times(4)).getKey(sampleDpopKid);

        // Verify no more interactions
        verifyNoMoreInteractions(scopeResolver, tokenStore, dpopKeyProvider);
    }

    private static void verifyTokenRequestHeaders(HttpHeaders headers, String expectedNonce) throws Exception {
        assertEquals(sampleUserAgent, headers.get(USER_AGENT.value()).get());
        assertEquals(expectedNonce, SignedJWT.parse(headers.get(DPOP.value()).get()).getJWTClaimsSet().getClaim("nonce"));
        assertEquals("application/x-www-form-urlencoded", headers.get(CONTENT_TYPE.value()).get());
        assertEquals("application/json", headers.get(ACCEPT.value()).get());
    }

    private static void verifyResourceRequestHeaders(HttpHeaders headers, String expectedNonce) throws Exception {
        assertEquals(sampleUserAgent, headers.get(USER_AGENT.value()).get());
        assertEquals("DPoP %s".formatted(sampleAccessToken), headers.get(AUTHORIZATION.value()).get());
        assertEquals(expectedNonce, SignedJWT.parse(headers.get(DPOP.value()).get()).getJWTClaimsSet().getClaim("nonce"));
    }

    private static String extractClientAssertion(String formBody) {
        var pattern = Pattern.compile("client_assertion=([^&]+)");
        var matcher = pattern.matcher(formBody);
        assertTrue(matcher.find(), "client_assertion not found in request body");
        return matcher.group(1);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocksCloseable != null) {
            mocksCloseable.close();
        }
        logbackLogger.detachAppender(listAppender);
        listAppender.stop();
    }
}
