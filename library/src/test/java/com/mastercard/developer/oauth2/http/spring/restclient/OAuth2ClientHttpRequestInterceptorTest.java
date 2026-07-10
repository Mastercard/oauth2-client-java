package com.mastercard.developer.oauth2.http.spring.restclient;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.restclient.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.restclient.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.restclient.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.restclient.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.restclient.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.restclient.model.PetStatus;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

class OAuth2ClientHttpRequestInterceptorTest extends BaseClientTest {

    private static RestClient clientWithInterceptor(TestConfig testConfig) {
        var interceptor = new OAuth2ClientHttpRequestInterceptor(testConfig.getOAuth2Config());
        return RestClient.builder().requestInterceptor(interceptor).build();
    }

    @ParameterizedTest
    @MethodSource("testConfigProvider")
    void client_ShouldSucceed(Supplier<TestConfig> configSupplier) throws Exception {
        // GIVEN
        TestConfig testConfig = configSupplier.get();
        RestClient restClient = clientWithInterceptor(testConfig);

        // WHEN: create resource
        var resource = createPostSpec(restClient, testConfig).exchange((request, response) -> {
            assertEquals(200, response.getStatusCode().value());
            return new String(response.getBody().readAllBytes());
        });
        // THEN
        assertNotNull(resource);
        assertTrue(resource.contains("id")); // Resource created
        var resourceId = readResourceId(resource);

        // WHEN: fetch resource
        resource = createGetSpec(restClient, testConfig, resourceId).retrieve().body(String.class);

        // THEN
        assertNotNull(resource);
        assertTrue(resource.contains("id")); // Resource fetched

        // WHEN: delete resource
        ResponseEntity<Void> entity = createDeleteSpec(restClient, testConfig, resourceId).retrieve().toBodilessEntity();

        // THEN
        assertEquals(HttpStatusCode.valueOf(204), entity.getStatusCode()); // Resource deleted
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        RestClient restClient = clientWithInterceptor(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.restclient.ApiClient(restClient);
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
    void openapiGeneratorClient_ShouldSucceed_WhenMastercardApi() {
        // GIVEN
        TestConfig testConfig = getMastercardConfig();
        RestClient restClient = clientWithInterceptor(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.petstore.restclient.ApiClient(restClient);
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
    void client_ShouldThrowHttpClientErrorException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        RestClient restClient = clientWithInterceptor(testConfig);

        // WHEN
        RestClient.ResponseSpec responseSpec = createPostSpec(restClient, testConfig).retrieve(); // "retrieve" throws HttpClientErrorException / HttpServerErrorException on error status codes
        var ex = assertThrows(HttpClientErrorException.class, responseSpec::toBodilessEntity);

        // THEN
        assertEquals(400, ex.getStatusCode().value());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void client_ShouldThrowHttpClientErrorException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        RestClient restClient = clientWithInterceptor(testConfig);

        // WHEN
        RestClient.ResponseSpec responseSpec = createPostSpec(restClient, testConfig).retrieve(); // "retrieve" throws HttpClientErrorException / HttpServerErrorException on error status codes
        var ex = assertThrows(HttpClientErrorException.class, responseSpec::toBodilessEntity);

        // THEN
        assertEquals(403, ex.getStatusCode().value());
        assertEquals(
            "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
            Objects.requireNonNull(ex.getResponseHeaders()).getFirst(WWW_AUTHENTICATE.value())
        );
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void openapiGeneratorClient_ShouldThrowHttpClientErrorException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        RestClient restClient = clientWithInterceptor(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.restclient.ApiClient(restClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(HttpClientErrorException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(400, ex.getStatusCode().value());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void openapiGeneratorClient_ShouldThrowHttpClientErrorException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        RestClient restClient = clientWithInterceptor(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.restclient.ApiClient(restClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(HttpClientErrorException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(403, ex.getStatusCode().value());
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBodyAsString(), true);
    }

    /**
     * Adds default headers that are expected to be replaced. Servers will complain in case they are not.
     */
    private static Consumer<HttpHeaders> withDummyHeaders(Map<String, String> headerMap) {
        return headers -> {
            headers.set(USER_AGENT.value(), "Dummy");
            headers.set(AUTHORIZATION.value(), "Dummy");
            headers.set(DPOP.value(), "Dummy");
            headerMap.forEach(headers::set);
        };
    }

    private static RestClient.RequestBodySpec createPostSpec(RestClient restClient, TestConfig testConfig) {
        return restClient
            .post()
            .uri(testConfig.getCreateResourceUri())
            .headers(withDummyHeaders(Map.of(ACCEPT.value(), "application/json", CONTENT_TYPE.value(), "application/json")))
            .body(testConfig.getResourceJson());
    }

    private static RestClient.RequestHeadersSpec<?> createGetSpec(RestClient restClient, TestConfig testConfig, String resourceId) {
        return restClient
            .get()
            .uri(testConfig.getFetchResourceUri(resourceId))
            .headers(withDummyHeaders(Map.of(ACCEPT.value(), "application/json")));
    }

    private static RestClient.RequestHeadersSpec<?> createDeleteSpec(RestClient restClient, TestConfig testConfig, String resourceId) {
        return restClient.delete().uri(testConfig.getDeleteResourceUri(resourceId)).headers(withDummyHeaders(Collections.emptyMap()));
    }
}
