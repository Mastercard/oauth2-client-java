package com.mastercard.developer.oauth2.http.spring.webclient;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.webclient.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.webclient.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.webclient.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.webclient.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.webclient.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.webclient.model.PetStatus;
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
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

class OAuth2FilterTest extends BaseClientTest {

    private static WebClient clientWithFilter(TestConfig testConfig) {
        WebClient.Builder baseBuilder = WebClient.builder();
        var filter = new OAuth2Filter(testConfig.getOAuth2Config(), baseBuilder);
        return baseBuilder.filter(filter).build();
    }

    @ParameterizedTest
    @MethodSource("testConfigProvider")
    void client_ShouldSucceed(Supplier<TestConfig> configSupplier) throws Exception {
        // GIVEN
        TestConfig testConfig = configSupplier.get();
        WebClient webClient = clientWithFilter(testConfig);

        // WHEN: create resource
        var resource = createPostSpec(webClient, testConfig)
            .exchangeToMono(response -> {
                assertEquals(200, response.statusCode().value());
                return response.bodyToMono(String.class);
            })
            .block();
        // THEN
        assertNotNull(resource);
        assertTrue(resource.contains("id")); // Resource created
        var resourceId = readResourceId(resource);

        // WHEN: fetch resource
        resource = createGetSpec(webClient, testConfig, resourceId).retrieve().bodyToMono(String.class).block();
        // THEN
        assertNotNull(resource);
        assertTrue(resource.contains("id")); // Resource fetched

        // WHEN: delete resource
        ResponseEntity<Void> entity = createDeleteSpec(webClient, testConfig, resourceId).retrieve().toBodilessEntity().block();
        // THEN
        assertNotNull(entity);
        assertEquals(HttpStatusCode.valueOf(204), entity.getStatusCode()); // Resource deleted
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        WebClient webClient = clientWithFilter(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.webclient.ApiClient(webClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN: create resource
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        Resource resource = api.createResource(newResource).block();
        // THEN
        assertNotNull(resource);
        assertNotNull(resource.getId());

        // WHEN: fetch resource
        resource = api.getResourceById(resource.getId()).block();
        // THEN
        assertNotNull(resource);

        // WHEN / THEN: delete resource
        api.deleteResourceById(resource.getId()).block();
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenMastercardApi() {
        {
            // GIVEN
            TestConfig testConfig = getMastercardConfig();
            WebClient webClient = clientWithFilter(testConfig);
            var client = new com.mastercard.developer.test.openapi_generator.petstore.webclient.ApiClient(webClient);
            client.setBasePath(testConfig.getApiBaseUrl());

            // WHEN: create resource
            var api = new PetsApi(client);
            var newDog = new NewDog();
            newDog.setName("Buddy");
            newDog.setColor("Golden");
            newDog.setStatus(new PetStatus().value("AVAILABLE"));
            newDog.setGender("MALE");
            newDog.setBreed("Golden Retriever");
            Dog dog = api.addDog(newDog).block();
            // THEN
            assertNotNull(dog);
            assertNotNull(dog.getId());

            // WHEN: fetch resource
            dog = api.getDog(dog.getId()).block();
            // THEN
            assertNotNull(dog);
            assertNotNull(dog.getId());

            // WHEN / THEN: delete resource
            api.deleteDog(dog.getId()).block();
        }
    }

    @Test
    void client_ShouldThrowWebClientResponseException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        WebClient webClient = clientWithFilter(testConfig);

        // WHEN
        Mono<String> stringMono = createPostSpec(webClient, testConfig).retrieve().bodyToMono(String.class); // "retrieve" throws WebClientResponseException on error status codes
        var ex = assertThrows(WebClientResponseException.class, stringMono::block);

        // THEN
        assertEquals(400, ex.getStatusCode().value());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void client_ShouldThrowWebClientResponseException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        WebClient webClient = clientWithFilter(testConfig);

        // WHEN
        Mono<String> stringMono = createPostSpec(webClient, testConfig).retrieve().bodyToMono(String.class); // "retrieve" throws WebClientResponseException on error status codes
        var ex = assertThrows(WebClientResponseException.class, stringMono::block);

        // THEN
        assertEquals(403, ex.getStatusCode().value());
        assertEquals(
            "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
            Objects.requireNonNull(ex.getHeaders()).getFirst(WWW_AUTHENTICATE.value())
        );
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void openapiGeneratorClient_ShouldThrowWebClientResponseException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        WebClient webClient = clientWithFilter(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.webclient.ApiClient(webClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        Mono<Resource> resourceMono = api.createResource(newResource);
        var ex = assertThrows(WebClientResponseException.class, resourceMono::block);

        // THEN
        assertEquals(400, ex.getStatusCode().value());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBodyAsString(), true);
    }

    @Test
    void openapiGeneratorClient_ShouldThrowWebClientResponseException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        WebClient webClient = clientWithFilter(testConfig);
        var client = new com.mastercard.developer.test.openapi_generator.fake.webclient.ApiClient(webClient);
        client.setBasePath(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        Mono<Resource> resourceMono = api.createResource(newResource);
        var ex = assertThrows(WebClientResponseException.class, resourceMono::block);

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

    private static WebClient.RequestHeadersSpec<?> createPostSpec(WebClient webClient, TestConfig testConfig) {
        return webClient
            .post()
            .uri(testConfig.getCreateResourceUri())
            .headers(withDummyHeaders(Map.of(ACCEPT.value(), "application/json", CONTENT_TYPE.value(), "application/json")))
            .bodyValue(testConfig.getResourceJson());
    }

    private static WebClient.RequestHeadersSpec<?> createGetSpec(WebClient webClient, TestConfig testConfig, String resourceId) {
        return webClient
            .get()
            .uri(testConfig.getFetchResourceUri(resourceId))
            .headers(withDummyHeaders(Map.of(ACCEPT.value(), "application/json")));
    }

    private static WebClient.RequestHeadersSpec<?> createDeleteSpec(WebClient webClient, TestConfig testConfig, String resourceId) {
        return webClient.delete().uri(testConfig.getDeleteResourceUri(resourceId)).headers(withDummyHeaders(Collections.emptyMap()));
    }
}
