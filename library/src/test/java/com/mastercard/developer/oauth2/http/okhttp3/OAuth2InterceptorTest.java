package com.mastercard.developer.oauth2.http.okhttp3;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static com.mastercard.developer.oauth2.test.fixtures.LiveResourceRetry.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseHttpClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.okhttp.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.okhttp.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.okhttp.ApiException;
import com.mastercard.developer.test.openapi_generator.petstore.okhttp.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.okhttp.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.okhttp.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.okhttp.model.PetStatus;
import okhttp3.*;
import org.junit.jupiter.api.Test;

class OAuth2InterceptorTest extends BaseHttpClientTest {

    private static OkHttpClient clientWithInterceptors(TestConfig testConfig) {
        OkHttpClient baseClient = new OkHttpClient.Builder().build();
        return baseClient.newBuilder().addInterceptor(new OAuth2Interceptor(testConfig.getOAuth2Config(), baseClient.newBuilder())).build();
    }

    @Override
    protected void clientShouldSucceed(TestConfig testConfig, boolean retryOn404) throws Exception {
        // GIVEN
        OkHttpClient httpClient = clientWithInterceptors(testConfig);

        // WHEN: create resource
        Request postRequest = createPostRequest(testConfig);
        var postCall = httpClient.newCall(postRequest);
        String resourceId;
        try (Response response = postCall.execute()) {
            // THEN
            assertEquals(200, response.code());
            assertNotNull(response.body());
            String resource = response.body().string();
            assertTrue(resource.contains("id")); // Resource created
            resourceId = readResourceId(resource);
        }

        // WHEN: fetch resource
        String resource = onNotFound(retryOn404, "GET", () -> {
            Request getRequest = createGetRequest(testConfig, resourceId);
            try (Response response = httpClient.newCall(getRequest).execute()) {
                if (retryOn404) {
                    failIfNotFound(response.code());
                }
                assertEquals(200, response.code());
                assertNotNull(response.body());
                return response.body().string();
            }
        });
        assertTrue(resource.contains("id")); // Resource fetched

        // WHEN: delete resource
        onNotFound(retryOn404, "DELETE", () -> {
            Request deleteRequest = createDeleteRequest(testConfig, resourceId);
            try (Response response = httpClient.newCall(deleteRequest).execute()) {
                if (retryOn404) {
                    failIfNotFound(response.code());
                }
                assertEquals(204, response.code()); // Resource deleted
                return null;
            }
        });
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.okhttp.ApiClient(httpClient);
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
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.petstore.okhttp.ApiClient(httpClient);
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
        var dogId = dog.getId();
        dog = onNotFound("GET", () -> api.getDog(dogId), error -> error instanceof ApiException ex && ex.getCode() == 404);
        // THEN
        assertNotNull(dog);
        assertNotNull(dog.getId());

        // WHEN / THEN: delete resource
        onNotFound(
            "DELETE",
            () -> {
                api.deleteDog(dogId);
                return null;
            },
            error -> error instanceof ApiException ex && ex.getCode() == 404
        );
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenAuthorizationServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        Request postRequest = createPostRequest(testConfig);
        var postCall = httpClient.newCall(postRequest);

        // WHEN
        try (Response response = postCall.execute()) {
            // THEN
            assertEquals(400, response.code());
            assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", response.body().string(), true);
        }
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenResourceServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        Request postRequest = createPostRequest(testConfig);
        var postCall = httpClient.newCall(postRequest);

        // WHEN
        try (Response response = postCall.execute()) {
            // THEN
            assertEquals(403, response.code());
            assertEquals(
                "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
                response.headers().get(WWW_AUTHENTICATE.value())
            );
            assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", response.body().string(), true);
        }
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.okhttp.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.okhttp.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(400, ex.getCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBody());
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        OkHttpClient httpClient = clientWithInterceptors(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.okhttp.ApiClient(httpClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.okhttp.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(403, ex.getCode());
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBody());
    }

    /**
     * Adds default headers that are expected to be replaced. Servers will complain in case they are not.
     */
    private static Request.Builder withDummyHeaders() {
        return new Request.Builder().header(USER_AGENT.value(), "Dummy").header(AUTHORIZATION.value(), "Dummy").header(DPOP.value(), "Dummy");
    }

    private static Request createPostRequest(TestConfig testConfig) {
        return withDummyHeaders()
            .url(testConfig.getCreateResourceUri())
            .header(ACCEPT.value(), "application/json")
            .header(CONTENT_TYPE.value(), "application/json")
            .post(RequestBody.create(testConfig.getResourceJson().getBytes()))
            .build();
    }

    private static Request createGetRequest(TestConfig testConfig, String resourceId) {
        return withDummyHeaders().url(testConfig.getFetchResourceUri(resourceId)).header(ACCEPT.value(), "application/json").get().build();
    }

    private static Request createDeleteRequest(TestConfig testConfig, String resourceId) {
        return withDummyHeaders().url(testConfig.getDeleteResourceUri(resourceId)).delete().build();
    }
}
