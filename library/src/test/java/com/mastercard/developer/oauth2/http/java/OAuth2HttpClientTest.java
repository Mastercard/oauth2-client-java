package com.mastercard.developer.oauth2.http.java;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseClientTest;
import com.mastercard.developer.oauth2.test.fixtures.TestConfig;
import com.mastercard.developer.test.openapi_generator.fake.java.api.ResourcesApi;
import com.mastercard.developer.test.openapi_generator.fake.java.model.Resource;
import com.mastercard.developer.test.openapi_generator.petstore.java.api.PetsApi;
import com.mastercard.developer.test.openapi_generator.petstore.java.model.Dog;
import com.mastercard.developer.test.openapi_generator.petstore.java.model.NewDog;
import com.mastercard.developer.test.openapi_generator.petstore.java.model.PetStatus;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("resource") // On JDK 11–20, java.net.http.HttpClient does not implement AutoCloseable
class OAuth2HttpClientTest extends BaseClientTest {

    @BeforeAll
    static void beforeAll() {
        System.setProperty("jdk.httpclient.HttpClient.log", "all");
    }

    @AfterAll
    static void afterAll() {
        System.clearProperty("jdk.httpclient.HttpClient.log");
    }

    private static HttpClient.Builder httpClient(TestConfig testConfig) {
        HttpClient.Builder baseBuilder = HttpClient.newBuilder();
        return OAuth2HttpClient.newBuilder(testConfig.getOAuth2Config(), baseBuilder);
    }

    @ParameterizedTest
    @MethodSource("testConfigProvider")
    void client_ShouldSucceed(Supplier<TestConfig> configSupplier) throws Exception {
        // GIVEN
        TestConfig testConfig = configSupplier.get();
        HttpClient client = httpClient(testConfig).build();

        // WHEN: create resource
        HttpRequest postRequest = createPostRequest(testConfig);
        HttpResponse<String> postResponse = client.send(postRequest, HttpResponse.BodyHandlers.ofString());
        // THEN
        assertEquals(200, postResponse.statusCode());
        assertNotNull(postResponse.body());
        String resource = postResponse.body();
        assertTrue(resource.contains("id")); // Resource created
        String resourceId = readResourceId(resource);

        // WHEN: fetch resource
        HttpRequest getRequest = createGetRequest(testConfig, resourceId);
        HttpResponse<String> getResponse = client.send(getRequest, HttpResponse.BodyHandlers.ofString());
        // THEN
        assertEquals(200, getResponse.statusCode());
        assertNotNull(getResponse.body());
        resource = getResponse.body();
        assertTrue(resource.contains("id")); // Resource fetched

        // WHEN: delete resource
        HttpRequest deleteRequest = createDeleteRequest(testConfig, resourceId);
        HttpResponse<Void> deleteResponse = client.send(deleteRequest, HttpResponse.BodyHandlers.discarding());
        // THEN
        assertEquals(204, deleteResponse.statusCode()); // Resource deleted
    }

    @Test
    void openapiGeneratorClient_ShouldSucceed_WhenFakeServers() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        var client = new com.mastercard.developer.test.openapi_generator.fake.java.ApiClient();
        client.setHttpClientBuilder(httpClient(testConfig));
        client.updateBaseUri(testConfig.getApiBaseUrl());

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
        {
            // GIVEN
            TestConfig testConfig = getMastercardConfig();
            var client = new com.mastercard.developer.test.openapi_generator.petstore.java.ApiClient();
            client.setHttpClientBuilder(httpClient(testConfig));
            client.updateBaseUri(testConfig.getApiBaseUrl());

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
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenAuthorizationServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", response.body(), true);
    }

    @Test
    void client_ShouldReturnErrorResponse_WhenResourceServerError() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, response.statusCode());
        assertEquals(
            "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"",
            response.headers().firstValue(WWW_AUTHENTICATE.value()).orElse(null)
        );
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", response.body(), true);
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenAuthorizationServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInvalidClientAssertionScenario(); // Force an authentication server error
        var client = new com.mastercard.developer.test.openapi_generator.fake.java.ApiClient();
        client.setHttpClientBuilder(httpClient(testConfig));
        client.updateBaseUri(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.java.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(400, ex.getCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", ex.getResponseBody());
    }

    @Test
    void openapiGeneratorClient_ShouldThrowApiException_WhenResourceServerError() {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        useInsufficientScopeScenario(); // Force a resource server error
        var client = new com.mastercard.developer.test.openapi_generator.fake.java.ApiClient();
        client.setHttpClientBuilder(httpClient(testConfig));
        client.updateBaseUri(testConfig.getApiBaseUrl());

        // WHEN
        var api = new ResourcesApi(client);
        var newResource = new Resource().id("1");
        var ex = assertThrows(com.mastercard.developer.test.openapi_generator.fake.java.ApiException.class, () -> api.createResource(newResource));

        // THEN
        assertEquals(403, ex.getCode());
        assertEquals("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}", ex.getResponseBody());
    }

    @Test
    void client_ShouldSupportStringBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());

        // THEN
        assertEquals(200, response.statusCode());
        assertEquals("{\"id\":\"1\"}", response.body(), true);
    }

    @Test
    void client_ShouldSupportStringBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());

        // THEN
        assertEquals(400, response.statusCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", response.body(), true);
    }

    @Test
    void client_ShouldSupportByteArrayBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<byte[]> response = client.send(postRequest, HttpResponse.BodyHandlers.ofByteArray());

        // THEN
        assertEquals(200, response.statusCode());
        assertEquals("{\"id\":\"1\"}", new String(response.body()), true);
    }

    @Test
    void client_ShouldSupportByteArrayBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<byte[]> response = client.send(postRequest, HttpResponse.BodyHandlers.ofByteArray());

        // THEN
        assertEquals(400, response.statusCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", new String(response.body()), true);
    }

    @Test
    void client_ShouldSupportInputStreamBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<InputStream> response = client.send(postRequest, HttpResponse.BodyHandlers.ofInputStream());

        // THEN
        assertEquals(200, response.statusCode());
        try (InputStream bodyStream = response.body()) {
            assertEquals("{\"id\":\"1\"}", new String(bodyStream.readAllBytes()), true);
        }
    }

    @Test
    void client_ShouldSupportInputStreamBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<InputStream> response = client.send(postRequest, HttpResponse.BodyHandlers.ofInputStream());

        // THEN
        assertEquals(400, response.statusCode());
        try (InputStream bodyStream = response.body()) {
            assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", new String(bodyStream.readAllBytes()), true);
        }
    }

    @Test
    void client_ShouldSupportLinesBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<Stream<String>> response = client.send(postRequest, HttpResponse.BodyHandlers.ofLines());

        // THEN
        assertEquals(200, response.statusCode());
        try (Stream<String> bodyStream = response.body()) {
            assertEquals("{\"id\":\"1\"}", bodyStream.collect(Collectors.joining()), true);
        }
    }

    @Test
    void client_ShouldSupportLinesBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<Stream<String>> response = client.send(postRequest, HttpResponse.BodyHandlers.ofLines());

        // THEN
        assertEquals(400, response.statusCode());
        try (Stream<String> bodyStream = response.body()) {
            assertEquals(
                "{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}",
                bodyStream.collect(Collectors.joining()),
                true
            );
        }
    }

    @Test
    void client_ShouldSupportReplacingBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.replacing("{\"id\":\"2\"}"));
        assertEquals(200, response.statusCode());

        // THEN
        assertEquals("{\"id\":\"2\"}", response.body(), true);
    }

    @Test
    void client_ShouldSupportReplacingBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.replacing("{\"id\":\"2\"}"));
        assertEquals(400, response.statusCode());

        // THEN
        assertEquals("{\"id\":\"2\"}", response.body(), true);
    }

    @Test
    void client_ShouldSupportFileBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<Path> response = client.send(postRequest, HttpResponse.BodyHandlers.ofFile(Files.createTempFile("internalResponse", ".json")));
        assertEquals(200, response.statusCode());

        // THEN
        assertEquals("{\"id\":\"1\"}", Files.readString(response.body()), true);
    }

    @Test
    void client_ShouldSupportFileBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<Path> response = client.send(postRequest, HttpResponse.BodyHandlers.ofFile(Files.createTempFile("internalResponse", ".json")));
        assertEquals(400, response.statusCode());

        // THEN
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}", Files.readString(response.body()), true);
    }

    @Test
    void client_ShouldSupportDiscardingBodyHandler_WhenResponseFromResourceServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);

        // WHEN
        HttpResponse<Void> response = client.send(postRequest, HttpResponse.BodyHandlers.discarding());

        // THEN
        assertEquals(200, response.statusCode());
    }

    @Test
    void client_ShouldSupportDiscardingBodyHandler_WhenResponseFromAuthorizationServer() throws Exception {
        // GIVEN
        TestConfig testConfig = getFakeConfig();
        HttpClient client = httpClient(testConfig).build();
        HttpRequest postRequest = createPostRequest(testConfig);
        useInvalidClientAssertionScenario(); // Force an authentication server error

        // WHEN
        HttpResponse<Void> response = client.send(postRequest, HttpResponse.BodyHandlers.discarding());

        // THEN
        assertEquals(400, response.statusCode());
    }

    /**
     * Adds default headers that are expected to be replaced. Servers will complain in case they are not.
     */
    private static HttpRequest.Builder withDummyHeaders() {
        return HttpRequest.newBuilder().header(USER_AGENT.value(), "Dummy").header(AUTHORIZATION.value(), "Dummy").header(DPOP.value(), "Dummy");
    }

    private static HttpRequest createPostRequest(TestConfig testConfig) throws URISyntaxException {
        return withDummyHeaders()
            .uri(new URI(testConfig.getCreateResourceUri()))
            .header(ACCEPT.value(), "application/json")
            .header(CONTENT_TYPE.value(), "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(testConfig.getResourceJson()))
            .build();
    }

    private static HttpRequest createGetRequest(TestConfig testConfig, String resourceId) throws URISyntaxException {
        return withDummyHeaders()
            .uri(new URI(testConfig.getFetchResourceUri(resourceId)))
            .header(ACCEPT.value(), "application/json")
            .GET()
            .build();
    }

    private static HttpRequest createDeleteRequest(TestConfig testConfig, String resourceId) throws URISyntaxException {
        return withDummyHeaders()
            .uri(new URI(testConfig.getDeleteResourceUri(resourceId)))
            .DELETE()
            .build();
    }
}
