package com.mastercard.developer.oauth2.internal.json;

import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JsonProvidersTest {

    static Stream<Arguments> jsonProviders() {
        return Stream.of(createConfigArgument(JsonOrgJsonProvider::new), createConfigArgument(JacksonJsonProvider::new), createConfigArgument(GsonJsonProvider::new));
    }

    private static Arguments createConfigArgument(Supplier<JsonProvider> jsonProviderSupplier) {
        JsonProvider provider = jsonProviderSupplier.get();
        return Arguments.of(Named.of(provider.getClass().getSimpleName(), provider));
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void parse_ShouldParseAccessTokenResponse(JsonProvider provider) throws Exception {
        // GIVEN
        var json = """
            {
              "access_token": "eyJ4NXQjUzI1NiI6Ii...oPIq4PZf2WaMxLow",
              "token_type": "DPoP",
              "expires_in": 900,
              "scope": "service:scope1 service:scope2"
            }""";

        // WHEN
        Map<String, Object> map = provider.parse(json);

        // THEN
        assertEquals("eyJ4NXQjUzI1NiI6Ii...oPIq4PZf2WaMxLow", map.get("access_token"));
        assertEquals("DPoP", map.get("token_type"));
        assertEquals(900, ((Number) map.get("expires_in")).intValue());
        assertEquals("service:scope1 service:scope2", map.get("scope"));
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void parse_ShouldParseExpireInDecimalValues(JsonProvider provider) throws Exception {
        // GIVEN
        var json = """
            {
              "expires_in": 900.0
            }""";

        // WHEN
        Map<String, Object> map = provider.parse(json);

        // THEN
        assertEquals(900, ((Number) map.get("expires_in")).intValue());
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void parse_ShouldParseJwk(JsonProvider provider) throws Exception {
        // GIVEN
        var json = Files.readString(Paths.get("./src/test/resources/keys/jwk/test_ec.json"), StandardCharsets.UTF_8);

        // WHEN
        Map<String, Object> map = provider.parse(json);

        // THEN
        assertNotNull(map.get("kty"));
        assertEquals("EC", map.get("kty"));
        assertEquals("P-256", map.get("crv"));
        assertEquals("QSmrwP5VQoH7PzWJ3ZTKhG7S_Wr1zDP8ko6-z7SLTa8", map.get("d"));
        assertEquals("cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc", map.get("x"));
        assertEquals("89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8", map.get("y"));
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void write_ShouldSerializeJwtHeaderToJson(JsonProvider provider) throws Exception {
        // GIVEN
        var map = Map.of(
            "alg",
            "ES256",
            "typ",
            "dpop+jwt",
            "jwk",
            Map.of("kty", "EC", "crv", "P-256", "x", "cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc", "y", "89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8")
        );

        // WHEN
        String json = provider.write(map);

        // THEN
        var expectedJson = """
            {
              "alg": "ES256",
              "typ": "dpop+jwt",
              "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc",
                "y": "89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8"
              }
            }
            """;
        assertEquals(expectedJson, json, true);
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void write_ShouldSerializeJwtPayloadToJson(JsonProvider provider) throws Exception {
        // GIVEN
        var map = Map.<String, Object>of(
            "jti",
            "1484862699019414",
            "htm",
            "POST",
            "htu",
            "https://sandbox.api.mastercard.com/oauth/token",
            "iat",
            1760028605L,
            "exp",
            1760028725L,
            "nonce",
            "5e8972513327f0b3670b21f308cf5e8e"
        );

        // WHEN
        String json = provider.write(map);

        // THEN
        var expectedJson = """
            {
              "jti": "1484862699019414",
              "htm": "POST",
              "htu": "https://sandbox.api.mastercard.com/oauth/token",
              "iat": 1760028605,
              "exp": 1760028725,
              "nonce": "5e8972513327f0b3670b21f308cf5e8e"
            }
            """;
        assertEquals(expectedJson, json, true);
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void parse_ShouldThrowExceptionWithCause_WhenInvalidJson(JsonProvider provider) {
        // GIVEN
        var invalidJson = "Not a valid JSON string";

        // WHEN & THEN
        var ex = assertThrows(OAuth2ClientJsonException.class, () -> provider.parse(invalidJson));
        assertEquals("Failed to read JSON", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @ParameterizedTest
    @MethodSource("jsonProviders")
    void tryParse_ShouldReturnEmpty_WhenInvalidJson(JsonProvider provider) {
        // GIVEN
        var invalidJson = "Not a valid JSON string";

        // WHEN & THEN
        assertTrue(provider.tryParse(invalidJson).isEmpty());
    }
}
