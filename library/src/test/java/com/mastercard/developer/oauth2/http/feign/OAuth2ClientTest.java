package com.mastercard.developer.oauth2.http.feign;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static com.mastercard.developer.oauth2.test.fixtures.LiveResourceRetry.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mastercard.developer.oauth2.test.fixtures.BaseHttpClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.feign.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.feign.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.feign.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.feign.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.feign.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.feign.model.PetStatus;
import feign.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;

@SuppressWarnings("OptionalGetWithoutIsPresent") // Simpler assertions
class OAuth2ClientTest extends BaseHttpClientTest {

    @Override
    protected void clientShouldSucceed(TestConfig testConfig, boolean retryOn404) throws Exception {
        // GIVEN
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());

        // WHEN: create resource
        var postRequest = createPostRequest(testConfig);
        String resourceId;
        try (Response postResponse = feignClient.execute(postRequest, new Request.Options())) {
            // THEN
            assertEquals(200, postResponse.status());
            assertNotNull(postResponse.body());
            String resource = Util.toString(postResponse.body().asReader(StandardCharsets.UTF_8));
            assertTrue(resource.contains("id")); // Resource created
            resourceId = readResourceId(resource);
        }

        // WHEN: fetch resource
        String resource = onNotFound(retryOn404, "GET", () -> {
            var getRequest = createGetRequest(testConfig, resourceId);
            try (Response getResponse = feignClient.execute(getRequest, new Request.Options())) {
                if (retryOn404) {
                    failIfNotFound(getResponse.status());
                }
                assertEquals(200, getResponse.status());
                assertNotNull(getResponse.body());
                return Util.toString(getResponse.body().asReader(StandardCharsets.UTF_8));
            }
        });
        assertTrue(resource.contains("id")); // Resource fetched

        // WHEN: delete resource
        onNotFound(retryOn404, "DELETE", () -> {
            var deleteRequest = createDeleteRequest(testConfig, resourceId);
            try (Response deleteResponse = feignClient.execute(deleteRequest, new Request.Options())) {
                if (retryOn404) {
                    failIfNotFound(deleteResponse.status());
                }
                assertEquals(204, deleteResponse.status()); // Resource deleted
                return null;
            }
        });
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var client = new com.mastercard.developer.test.openapi_generator.fake.feign.ApiClient();
        client.setBasePath(testConfig.getApiBaseUrl());
        client.getFeignBuilder().client(feignClient).logLevel(Logger.Level.HEADERS);

        // WHEN: create resource
        ResourcesApi api = client.buildClient(ResourcesApi.class);
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
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var client = new com.mastercard.developer.test.openapi_generator.petstore.feign.ApiClient().setBasePath(testConfig.getApiBaseUrl());
        client.setBasePath(testConfig.getApiBaseUrl());
        client.getFeignBuilder().client(feignClient).logLevel(Logger.Level.HEADERS);

        // WHEN: create resource
        PetsApi api = client.buildClient(PetsApi.class);
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
        dog = onNotFound("GET", () -> api.getDog(dogId), error -> error instanceof FeignException ex && ex.status() == 404);
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
            error -> error instanceof FeignException ex && ex.status() == 404
        );
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenAuthorizationServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var postRequest = createPostRequest(testConfig);

        // WHEN
        try (Response postResponse = feignClient.execute(postRequest, new Request.Options())) {
            // THEN
            assertEquals(400, postResponse.status());
            assertEquals(
                "{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}",
                Util.toString(postResponse.body().asReader(StandardCharsets.UTF_8))
            );
        }
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenResourceServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var postRequest = createPostRequest(testConfig);

        // WHEN
        try (Response postResponse = feignClient.execute(postRequest, new Request.Options())) {
            // THEN
            assertEquals(403, postResponse.status());
            assertEquals(
                "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
                postResponse.headers().get(WWW_AUTHENTICATE.value()).iterator().next()
            );
            assertEquals(
                "{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}",
                Util.toString(postResponse.body().asReader(StandardCharsets.UTF_8))
            );
        }
    }

    @Test
    void openapiGeneratorClient_ShouldThrowFeignException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var client = new com.mastercard.developer.test.openapi_generator.fake.feign.ApiClient().setBasePath(testConfig.getApiBaseUrl());
        client.setBasePath(testConfig.getApiBaseUrl());
        client.getFeignBuilder().client(feignClient).logLevel(Logger.Level.HEADERS);

        // WHEN
        ResourcesApi api = client.buildClient(ResourcesApi.class);
        var newResource = new Resource().id("1");
        var ex = assertThrows(FeignException.BadRequest.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(400, ex.status());
        assertEquals(
            "{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}",
            StandardCharsets.UTF_8.decode(ex.responseBody().get()).toString()
        );
    }

    @Test
    void openapiGeneratorClient_ShouldThrowFeignException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        Client feignClient = new OAuth2Client(testConfig.getOAuth2Config());
        var client = new com.mastercard.developer.test.openapi_generator.fake.feign.ApiClient().setBasePath(testConfig.getApiBaseUrl());
        client.setBasePath(testConfig.getApiBaseUrl());
        client.getFeignBuilder().client(feignClient).logLevel(Logger.Level.HEADERS);

        // WHEN
        ResourcesApi api = client.buildClient(ResourcesApi.class);
        var newResource = new Resource().id("1");
        var ex = assertThrows(FeignException.Forbidden.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(403, ex.status());
        assertEquals(
            "{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}",
            StandardCharsets.UTF_8.decode(ex.responseBody().get()).toString()
        );
    }

    /**
     * Adds default headers that are expected to be replaced. Servers will complain in case they are not.
     */
    private static Map<String, Collection<String>> withDummyHeaders(Map<String, Collection<String>> headers) {
        var finalHeaders = new HashMap<String, Collection<String>>();
        finalHeaders.put(USER_AGENT.value(), List.of("Dummy"));
        finalHeaders.put(AUTHORIZATION.value(), List.of("Dummy"));
        finalHeaders.put(DPOP.value(), List.of("Dummy"));
        finalHeaders.putAll(headers);
        return finalHeaders;
    }

    private static Request createPostRequest(TestConfig testConfig) {
        return Request.create(
            Request.HttpMethod.POST,
            testConfig.getCreateResourceUri(),
            withDummyHeaders(Map.of(ACCEPT.value(), List.of("application/json"), CONTENT_TYPE.value(), List.of("application/json"))),
            testConfig.getResourceJson().getBytes(),
            Charset.defaultCharset(),
            null
        );
    }

    private static Request createGetRequest(TestConfig testConfig, String resourceId) {
        return Request.create(
            Request.HttpMethod.GET,
            testConfig.getFetchResourceUri(resourceId),
            withDummyHeaders(Map.of(ACCEPT.value(), List.of("application/json"))),
            Request.Body.empty(),
            null
        );
    }

    private static Request createDeleteRequest(TestConfig testConfig, String resourceId) {
        return Request.create(Request.HttpMethod.DELETE, testConfig.getDeleteResourceUri(resourceId), withDummyHeaders(Collections.emptyMap()), Request.Body.empty(), null);
    }
}
