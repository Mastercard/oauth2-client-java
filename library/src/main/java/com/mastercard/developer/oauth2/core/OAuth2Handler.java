package com.mastercard.developer.oauth2.core;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.access_token.AccessToken;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenFilter;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenStore;
import com.mastercard.developer.oauth2.core.dpop.DPoPKey;
import com.mastercard.developer.oauth2.core.dpop.DPoPKeyProvider;
import com.mastercard.developer.oauth2.core.scope.ScopeResolver;
import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import com.mastercard.developer.oauth2.internal.jose.Jwk;
import com.mastercard.developer.oauth2.internal.jose.Jws;
import com.mastercard.developer.oauth2.internal.jose.JwsAlgorithm;
import com.mastercard.developer.oauth2.internal.jose.Jwt;
import com.mastercard.developer.oauth2.internal.json.JsonProvider;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Acts as an orchestrator for adding OAuth2 authentication to API requests.
 * This class uses the adapter pattern ({@link HttpAdapter}) to work with different HTTP clients,
 * making it client-agnostic.
 */
@SuppressWarnings("squid:S00119") // For readability, we keep generic type names as 'Request' and 'Response'
public final class OAuth2Handler {

    private final OAuth2Config config;
    private final DPoPKeyProvider dpopKeyProvider;
    private final ScopeResolver scopeResolver;
    private final AccessTokenStore tokenStore;
    private volatile String nonce;
    private static final Logger logger = LoggerFactory.getLogger(OAuth2Handler.class);

    /**
     * Creates a new instance of this class with the given configuration.
     */
    public OAuth2Handler(OAuth2Config config) {
        this.config = config;
        this.dpopKeyProvider = config.getDPoPKeyProvider();
        this.scopeResolver = config.getScopeResolver();
        this.tokenStore = config.getAccessTokenStore();
    }

    /**
     *  Main entry point that coordinates the entire OAuth2 flow for each intercepted request.
     */
    public <Request, Response> Response execute(Request request, HttpAdapter<Request, Response> adapter) throws Exception {
        String method = adapter.getMethod(request);
        URL resourceUrl = adapter.getUrl(request);
        logger.info("Intercepting API request: {} {}", method, resourceUrl);
        logger.debug("Using configuration:\n{}", config);

        // Obtain a stable DPoP key for this cycle
        DPoPKey dpopKey = getDPoPKey();

        // Retrieve scopes needed for the request
        Set<String> scopes = getScopes(request, adapter);

        // Retrieve an access token (from the store or new)
        AccessTokenResult<Response> result = retrieveAccessToken(request, adapter, scopes, dpopKey);
        if (result.hasError()) {
            return result.errorResponse;
        }

        // Call the resource server with the access token
        String accessToken = result.accessToken().tokenValue();
        return sendOriginalRequest(request, adapter, accessToken, dpopKey.getKeyId());
    }

    private DPoPKey getDPoPKey() {
        logger.info("Retrieving DPoP key");
        DPoPKey dpopKey = dpopKeyProvider.getCurrentKey();
        logger.debug("DPoP key ID: {}", dpopKey.getKeyId());
        logger.debug("DPoP public key:\n{}", dpopKey.getKeyPair().getPublic());
        return dpopKey;
    }

    private <Request, Response> Set<String> getScopes(Request originalRequest, HttpAdapter<Request, Response> adapter) throws Exception {
        logger.info("Resolving scopes");
        URL resourceUrl = adapter.getUrl(originalRequest);
        String method = adapter.getMethod(originalRequest);
        Set<String> scopes = scopeResolver.resolve(method, resourceUrl);
        logger.debug("Scopes: {}", scopes);
        return scopes;
    }

    private <Request, Response> AccessTokenResult<Response> retrieveAccessToken(
        Request originalRequest,
        HttpAdapter<Request, Response> adapter,
        Set<String> scopes,
        DPoPKey dpopKey
    ) throws Exception {
        String jkt = Jwk.fromKey(dpopKey.getKeyPair().getPublic()).computeThumbprint();
        logger.info("Checking access token store");
        var filter = AccessTokenFilter.byJktAndScopes(jkt, scopes);
        logger.debug("Filter: {}", filter);
        Optional<AccessToken> existingToken = tokenStore.get(filter);
        if (existingToken.isPresent()) {
            AccessToken accessToken = existingToken.get();
            logger.debug("Valid access token found: {}", accessToken);
            return AccessTokenResult.from(accessToken);
        }

        logger.info("No valid access token, requesting new access token: POST {}", config.getTokenEndpoint());
        String dpopKeyId = dpopKey.getKeyId();
        Response tokenResponse = makeAccessTokenRequest(originalRequest, adapter, dpopKeyId, scopes);
        if (mustRetryRequest(adapter, tokenResponse)) {
            adapter.close(tokenResponse);
            logger.debug("`use_dpop_nonce` returned, retrying access token request");
            tokenResponse = makeAccessTokenRequest(originalRequest, adapter, dpopKeyId, scopes);
        }

        String body = adapter.readBody(tokenResponse).orElse(null);
        int statusCode = adapter.getStatusCode(tokenResponse);
        if (isSuccess(statusCode)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Access token request succeeded (HTTP {}), body: {}", statusCode, logBody(body));
            }
        } else {
            if (logger.isErrorEnabled()) {
                logger.error("Access token request failed (HTTP {}), body: {}", statusCode, logBody(body));
            }
            return AccessTokenResult.from(tokenResponse);
        }
        adapter.close(tokenResponse);
        AccessTokenResponse accessTokenResponse = parseAccessTokenJson(body);
        var accessToken = new AccessToken(config.getClientId(), accessTokenResponse.scopes(), accessTokenResponse.expiry(), jkt, accessTokenResponse.tokenValue());
        logger.debug("Adding access token to store: {}", accessToken);
        tokenStore.put(accessToken);
        return AccessTokenResult.from(accessToken);
    }

    private <Request, Response> Response makeAccessTokenRequest(Request originalRequest, HttpAdapter<Request, Response> adapter, String dpopKeyId, Set<String> scopes)
        throws Exception {
        URL tokenUrl = config.getTokenEndpoint();
        String clientId = config.getClientId();
        if (logger.isDebugEnabled()) {
            logger.debug("Creating token request DPoP proof (nonce: {})", logNonce(nonce));
        }
        String dpopProof = createTokenRequestDPoP(config, dpopKeyId, nonce);
        logger.debug("Token request DPoP proof: {}", dpopProof);
        var scope = String.join(" ", scopes);
        logger.debug("Creating client assertion");
        String clientAssertion = createClientAssertion(config);
        logger.debug("Client assertion: {}", clientAssertion);
        String formBody = createAccessTokenRequestBody(clientId, scope, clientAssertion);
        logger.debug("Sending access token request with body: {}", formBody);
        var headers = new HttpHeaders()
            .add(USER_AGENT, config.getUserAgent())
            .add(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .add(ACCEPT, "application/json")
            .add(DPOP, dpopProof);
        Response response = adapter.sendAccessTokenRequest(originalRequest, tokenUrl, formBody, headers);
        updateNonce(adapter, response);
        return response;
    }

    private <Request, Response> Response sendOriginalRequest(Request request, HttpAdapter<Request, Response> adapter, String accessToken, String dpopKeyId) throws Exception {
        String method = adapter.getMethod(request);
        URL resourceUrl = adapter.getUrl(request);
        logger.info("Making API call: {} {}", method, resourceUrl);
        Response response = makeResourceRequest(request, adapter, accessToken, dpopKeyId);
        if (mustRetryRequest(adapter, response)) {
            adapter.close(response);
            logger.debug("`use_dpop_nonce` returned, retrying API call");
            response = makeResourceRequest(request, adapter, accessToken, dpopKeyId);
        }
        String body = adapter.readBody(response).orElse(null);
        int statusCode = adapter.getStatusCode(response);
        if (isSuccess(statusCode)) {
            if (logger.isDebugEnabled()) {
                logger.debug("API call successful (HTTP {}), body: {}", statusCode, logBody(body));
            }
        } else {
            if (logger.isErrorEnabled()) {
                logger.error("API call failed (HTTP {}), body: {}", statusCode, logBody(body));
            }
        }
        return response;
    }

    private <Request, Response> Response makeResourceRequest(Request request, HttpAdapter<Request, Response> adapter, String accessToken, String dpopKeyId) throws Exception {
        String method = adapter.getMethod(request);
        String resourceUrl = adapter.getUrl(request).toString();
        if (logger.isDebugEnabled()) {
            logger.debug("Creating resource request DPoP proof (nonce: {})", logNonce(nonce));
        }
        String dpopProof = createResourceRequestDPoP(config, dpopKeyId, method, resourceUrl, accessToken, nonce);
        logger.debug("Resource request DPoP proof: {}", dpopProof);
        var headers = new HttpHeaders().add(USER_AGENT, config.getUserAgent()).add(AUTHORIZATION, "DPoP " + accessToken).add(DPOP, dpopProof);
        logger.debug("Sending request");
        Response response = adapter.sendResourceRequest(request, headers);
        updateNonce(adapter, response);
        return response;
    }

    /**
     * Retry requests returning a `use_dpop_nonce` error (HTTP 400/401), as per:
     * <ul>
     * <li><a href="https://datatracker.ietf.org/doc/html/rfc9449#section-8">RFC 9449 Section 8</a> (Authorization Server)</li>
     * <li><a href="https://datatracker.ietf.org/doc/html/rfc9449#section-9">RFC 9449 Section 9</a> (Resource Server)</li>
     * </ul>
     */
    private <Request, Response> boolean mustRetryRequest(HttpAdapter<Request, Response> adapter, Response response) throws Exception {
        int statusCode = adapter.getStatusCode(response);
        if (statusCode != 401 && statusCode != 400) {
            return false;
        }
        String body = adapter.readBody(response).orElse(null);
        Map<String, Object> jsonMap = JsonProvider.getInstance().tryParse(body).orElse(Map.of());
        if ("use_dpop_nonce".equals(jsonMap.get("error"))) {
            return true;
        }
        Optional<String> wwwAuthenticate = adapter.getHeader(response, WWW_AUTHENTICATE.value());
        return wwwAuthenticate.map(header -> header.contains("use_dpop_nonce")).orElse(false);
    }

    /**
     * Check if a nonce was returned in the response headers and update the current nonce accordingly.
     * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449">OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
     */
    private <Request, Response> void updateNonce(HttpAdapter<Request, Response> adapter, Response response) throws Exception {
        if (response == null) {
            return;
        }
        Optional<String> dpopNonce = adapter.getHeader(response, DPOP_NONCE.value());
        if (dpopNonce.isPresent() && !dpopNonce.get().isEmpty()) {
            nonce = dpopNonce.get();
            logger.debug("New DPoP nonce from server: {}", nonce);
        }
    }

    /**
     * Creates a private_key_jwt client assertion for OAuth2 token requests.
     * The assertion is signed with the client's private key.
     * See: <a href="https://oauth.net/private-key-jwt/">Private Key JWT</a>
     */
    public static String createClientAssertion(OAuth2Config config) {
        try {
            PrivateKey clientKey = config.getClientKey();
            String clientId = config.getClientId();
            String kid = config.getKid();
            String audience = config.getIssuer().toString(); // The authorization server's issuer identifier value as per https://openid.bitbucket.io/fapi/fapi-security-profile-2_0.html#name-general-requirements-2
            Duration clockSkewTolerance = config.getClockSkewTolerance();
            var alg = JwsAlgorithm.fromKey(clientKey);
            var now = Instant.now();
            long issuedAt = now.getEpochSecond();
            long expiresAt = now.plusSeconds(90).plusSeconds(clockSkewTolerance.getSeconds()).getEpochSecond(); // 1.5 min + clock skew tolerance
            long notBefore = now.minusSeconds(clockSkewTolerance.getSeconds()).getEpochSecond();

            var jwt = new Jwt();
            jwt.addHeaderParam("alg", JwsAlgorithm.fromKey(clientKey));
            jwt.addHeaderParam("typ", "JWT");
            jwt.addHeaderParam("kid", kid);
            jwt.addClaim("jti", randomJti());
            jwt.addClaim("sub", clientId);
            jwt.addClaim("iss", clientId);
            jwt.addClaim("aud", audience);
            jwt.addClaim("iat", issuedAt);
            jwt.addClaim("exp", expiresAt);
            jwt.addClaim("nbf", notBefore);

            Jws.sign(jwt, clientKey, alg);
            return jwt.getSerialized();
        } catch (OAuth2ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to create client assertion", e);
        }
    }

    /**
     * Creates a DPoP proof token for OAuth2 token endpoint requests.
     * This token proves possession of the DPoP key pair when requesting an access token.
     */
    public static String createTokenRequestDPoP(OAuth2Config config, String dpopKeyId, String nonceOrNull) {
        return createDPoP(config, dpopKeyId, "POST", config.getTokenEndpoint().toString(), null, nonceOrNull);
    }

    /**
     * Creates a DPoP proof token for resource access requests.
     * This token proves possession of the DPoP key pair and binds it to the access token.
     */
    public static String createResourceRequestDPoP(OAuth2Config config, String dpopKeyId, String htm, String resourceUrl, String accessToken, String nonceOrNull) {
        return createDPoP(config, dpopKeyId, htm, resourceUrl, computeAth(accessToken), nonceOrNull);
    }

    /**
     * Parses an OAuth2 token response JSON.
     * Example:
     * <pre>
     * {
     *   "access_token": "eyJ4NXQjUzI1NiI6Ii1sb...LTE69XYj5oPIq4PZf2WaMxLow",
     *   "token_type": "DPoP",
     *   "expires_in": 900,
     *   "scope": "service:scope1 service:scope2"
     * }
     * </pre>
     * See: <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">RFC 6749 Section 5.1</a>
     */
    public static AccessTokenResponse parseAccessTokenJson(String accessTokenResponse) {
        try {
            if (accessTokenResponse == null || accessTokenResponse.isBlank()) {
                throw new OAuth2ClientException("Empty access token response");
            }
            Map<String, Object> jsonMap = JsonProvider.getInstance().parse(accessTokenResponse);
            String tokenValue = (String) jsonMap.get("access_token");
            if (null == tokenValue) {
                throw new OAuth2ClientException("Missing value in access token response: access_token");
            }
            var expiresInSeconds = (Number) jsonMap.get("expires_in");
            if (null == expiresInSeconds) {
                throw new OAuth2ClientException("Missing value in access token response: expires_in");
            }
            Instant expiry = Instant.now().plusSeconds(expiresInSeconds.intValue());
            String scopeNode = (String) jsonMap.get("scope");
            Set<String> scopes = (scopeNode == null) ? Set.of() : Set.of(scopeNode.trim().split("\\s+"));
            return new AccessTokenResponse(tokenValue, scopes, expiry);
        } catch (OAuth2ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to parse JSON access token response", e);
        }
    }

    /**
     * Model for the response from an OAuth2 token endpoint.
     * See: <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">RFC 6749 Section 5.1</a>
     */
    public record AccessTokenResponse(String tokenValue, Set<String> scopes, Instant expiry) {}

    /**
     * Creates a URL-encoded request body for an OAuth2 client credentials token request.
     */
    public static String createAccessTokenRequestBody(String clientId, String scope, String clientAssertion) {
        return String.format(
            "client_id=%s&grant_type=client_credentials&scope=%s&client_assertion_type=%s&client_assertion=%s",
            urlEncode(clientId),
            urlEncode(scope),
            urlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            urlEncode(clientAssertion)
        );
    }

    /**
     * Creates a DPoP proof token.
     */
    private static String createDPoP(OAuth2Config config, String dpopKeyId, String htm, String url, String athOrNull, String nonceOrNull) {
        try {
            Duration clockSkewTolerance = config.getClockSkewTolerance();

            var now = Instant.now();
            long issuedAt = now.getEpochSecond();
            long expiresAt = now.plusSeconds(90).plusSeconds(clockSkewTolerance.getSeconds()).getEpochSecond(); // 1.5 min + clock skew tolerance
            KeyPair dpopKeyPair = config.getDPoPKeyProvider().getKey(dpopKeyId).getKeyPair();
            PrivateKey dpopPrivateKey = dpopKeyPair.getPrivate();
            PublicKey dpopPublicKey = dpopKeyPair.getPublic();
            var alg = JwsAlgorithm.fromKey(dpopPublicKey);
            var jwk = Jwk.fromKey(dpopPublicKey);

            var jwt = new Jwt();
            jwt.addHeaderParam("alg", alg);
            jwt.addHeaderParam("typ", "dpop+jwt");
            jwt.addHeaderParam("kid", dpopKeyId);
            jwt.addHeaderParam("jwk", jwk);
            jwt.addClaim("jti", randomJti());
            jwt.addClaim("htm", htm);
            jwt.addClaim("htu", stripQueryAndFragment(url));
            jwt.addClaim("iat", issuedAt);
            jwt.addClaim("exp", expiresAt);
            jwt.addClaim("ath", athOrNull);
            jwt.addClaim("nonce", nonceOrNull);

            Jws.sign(jwt, dpopPrivateKey, alg);
            return jwt.getSerialized();
        } catch (OAuth2ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to create DPoP proof", e);
        }
    }

    /**
     * Generates a 96 bits random JWT ID (jti) claim value
     * as per <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.2">DPoP Proof JWT Syntax</a>
     */
    private static String randomJti() {
        var randomBytes = new byte[12];
        try {
            SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        } catch (NoSuchAlgorithmException e) {
            new SecureRandom().nextBytes(randomBytes);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Computes a ath claim value as per
     * <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.2">DPoP Proof JWT Syntax</a>
     */
    private static String computeAth(String accessToken) throws OAuth2ClientException {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (OAuth2ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to compute access token hash", e);
        }
    }

    /**
     * Return the HTTP URI of the request without query and fragment parts.
     * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax">DPoP Proof JWT Syntax</a>
     */
    private static String stripQueryAndFragment(String resourceUrl) {
        try {
            var uri = new URI(resourceUrl);
            return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null).toString();
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to strip query and fragment parts from URL: %s".formatted(resourceUrl), e);
        }
    }

    private static String urlEncode(String string) {
        return URLEncoder.encode(string, StandardCharsets.UTF_8);
    }

    private static boolean isSuccess(int statusCode) {
        return statusCode / 100 == 2;
    }

    private static String logBody(String body) {
        return (body == null || body.isEmpty()) ? "<none>" : body;
    }

    private static String logNonce(String nonce) {
        return (nonce == null || nonce.isEmpty()) ? "<none>" : nonce;
    }

    private record AccessTokenResult<Response>(AccessToken accessToken, Response errorResponse) {
        static <Response> AccessTokenResult<Response> from(AccessToken accessToken) {
            return new AccessTokenResult<>(accessToken, null);
        }

        static <Response> AccessTokenResult<Response> from(Response errorResponse) {
            return new AccessTokenResult<>(null, errorResponse);
        }

        boolean hasError() {
            return errorResponse != null;
        }
    }
}
