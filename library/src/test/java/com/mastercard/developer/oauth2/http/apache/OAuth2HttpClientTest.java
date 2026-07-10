package com.mastercard.developer.oauth2.http.apache;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.apache.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.apache.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.apache.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.apache.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.apache.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.apache.model.PetStatus;
import java.util.function.Supplier;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class OAuth2HttpClientTest extends BaseClientTest {

    private static CloseableHttpClient httpClient(TestConfig testConfig) {
        return new OAuth2HttpClient(testConfig.getOAuth2Config());
    }

    @ParameterizedTest
    @MethodSource("testConfigProvider")
    void client_ShouldSucceed(Supplier<TestConfig> configSupplier) throws Exception {
        // GIVEN
        TestConfig testConfig = configSupplier.get();
        CloseableHttpClient httpClient = httpClient(testConfig);
        try (httpClient) {
            // WHEN: create resource
            var postRequest = createPostRequest(testConfig);
            String resource = httpClient.execute(postRequest, response -> {
                assertEquals(200, response.getCode());
                var entity = response.getEntity();
                return entity != null ? EntityUtils.toString(entity) : null;
            });
            // THEN
            assertNotNull(resource);
            assertTrue(resource.contains("id")); // Resource created
            var resourceId = readResourceId(resource);

            // WHEN: fetch resource
            var getRequest = createGetRequest(testConfig, resourceId);
            resource = httpClient.execute(getRequest, response -> {
                assertEquals(200, response.getCode());
                var entity = response.getEntity();
                return entity != null ? EntityUtils.toString(entity) : null;
            });
            // THEN
            assertNotNull(resource);
            assertTrue(resource.contains("id")); // Resource fetched

            // WHEN: delete resource
            var deleteRequest = createDeleteRequest(testConfig, resourceId);
            httpClient.execute(deleteRequest, response -> {
                // THEN
                assertEquals(204, response.getCode()); // Resource deleted
                return response;
            });
        }
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        CloseableHttpClient httpClient = httpClient(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.apache.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN: create resource
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        Resource resource = api.createResource(newResource);
        // THEN
        assertNotNull(resource);
        assertNotNull(resource.getId());

        // WHEN: fetch resource
        resource = api.getResourceById(resource.getId());
        // THEN
        assertNotNull(resource);

        // WHEN / THEN: delete resource
        api.deleteResourceById(resource.getId());
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenMastercardApi() throws Exception {
        // GIVEN
        TestConfig testConfig = getMastercardConfig();
        CloseableHttpClient httpClient = httpClient(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.petstore.apache.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN: create resource
        var api = new PetsApi(client);
        var newDog = new NewDog();
        newDog.setName("Buddy");
        newDog.setColor("Golden");
        newDog.setStatus(new PetStatus().value("AVAILABLE"));
        newDog.setGender("MALE");
        newDog.setBreed("Golden Retriever");
        Dog dog = api.addDog(newDog);
        // THEN
        assertNotNull(dog);
        assertNotNull(dog.getId());

        // WHEN: fetch resource
        dog = api.getDog(dog.getId());
        // THEN
        assertNotNull(dog);
        assertNotNull(dog.getId());

        // WHEN / THEN: delete resource
        api.deleteDog(dog.getId());
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenAuthorizationServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        var postRequest = createPostRequest(testConfig);

        CloseableHttpClient httpClient = httpClient(testConfig);
        try (httpClient) {
            // WHEN /  THEN
            httpClient.execute(postRequest, response -> {
                assertEquals(400, response.getCode());
                assertEquals(
                    "{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}",
                    EntityUtils.toString(response.getEntity())
                );
                return response;
            });
        }
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenResourceServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        var postRequest = createPostRequest(testConfig);

        CloseableHttpClient httpClient = httpClient(testConfig);
        try (httpClient) {
            // WHEN /  THEN
            httpClient.execute(postRequest, response -> {
                assertEquals(403, response.getCode());
                assertEquals(
                    "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
                    response.getHeader(WWW_AUTHENTICATE.value()).getValue()
                );
                try {
                    assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", EntityUtils.toString(response.getEntity()), true);
                } catch (Exception e) {
                    fail("Error response expected");
                }
                return response;
            });
        }
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        CloseableHttpClient httpClient = httpClient(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.apache.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.apache.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(400, ex.getCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBody());
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        CloseableHttpClient httpClient = httpClient(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.apache.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.apache.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(403, ex.getCode());
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBody());
    }

    @Test
    void constructor_ShouldUseDelegate() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();

        // Delegate behaviour
        // Call to the authorization server returns a successful response.
        // Then call to the resource server returns a successful response.
        var tokenResponse = mock(CloseableHttpResponse.class);
        when(tokenResponse.getCode()).thenReturn(200);
        when(tokenResponse.getFirstHeader(CONTENT_TYPE.value())).thenReturn(null);
        when(tokenResponse.getEntity()).thenReturn(new StringEntity(sampleAccessTokenResponse, ContentType.APPLICATION_JSON));

        var resourceResponse = mock(CloseableHttpResponse.class);
        when(resourceResponse.getCode()).thenReturn(200);
        when(resourceResponse.getEntity()).thenReturn(new StringEntity("{\"success\":\"true\"}", ContentType.APPLICATION_JSON));

        var delegate = mock(CloseableHttpClient.class);
        when(delegate.executeOpen(any(), any(), any()))
            .thenReturn(tokenResponse)
            .thenReturn(resourceResponse);

        var postRequest = createPostRequest(testConfig);

        // WHEN
        CloseableHttpClient httpClient = new OAuth2HttpClient(testConfig.getOAuth2Config(), delegate);
        httpClient.execute(postRequest, response -> {
            assertEquals(200, response.getCode());
            var body = EntityUtils.toString(response.getEntity());
            assertEquals(body, "{\"success\":\"true\"}", true);
            return response;
        });
        httpClient.close();

        // THEN: the delegate was used for both calls, and then closed
        verify(delegate, times(2)).executeOpen(any(), any(), any());
        verify(delegate).close();
    }

    /**
     * Adds default headers that are expected to be replaced. Servers will complain in case they are not.
     */
    private static ClassicRequestBuilder withDummyHeaders(ClassicRequestBuilder builder) {
        return builder.setHeader(USER_AGENT.value(), "Dummy").setHeader(AUTHORIZATION.value(), "Dummy").setHeader(DPOP.value(), "Dummy");
    }

    private static ClassicHttpRequest createPostRequest(TestConfig testConfig) {
        return withDummyHeaders(
            ClassicRequestBuilder.create("POST")
                .setUri(testConfig.getCreateResourceUri())
                .setHeader(ACCEPT.value(), "application/json")
                .setHeader(CONTENT_TYPE.value(), "application/json")
                .setEntity(testConfig.getResourceJson(), ContentType.APPLICATION_JSON)
        ).build();
    }

    private static ClassicHttpRequest createGetRequest(TestConfig testConfig, String resourceId) {
        return withDummyHeaders(ClassicRequestBuilder.create("GET").setUri(testConfig.getFetchResourceUri(resourceId)).setHeader(ACCEPT.value(), "application/json")).build();
    }

    private static ClassicHttpRequest createDeleteRequest(TestConfig testConfig, String resourceId) {
        return withDummyHeaders(ClassicRequestBuilder.create("DELETE").setUri(testConfig.getDeleteResourceUri(resourceId))).build();
    }
}
