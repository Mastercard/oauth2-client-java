package com.mastercard.developer.oauth2.keys;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class KeyLoaderTest {

    @ParameterizedTest
    @CsvSource({
        "pkcs8/test_key_pkcs8-2048.der",
        "pkcs8/test_key_pkcs8-4096.der",
        "pkcs8/test_key_pkcs8-2048.pem",
        "pkcs8/test_key_pkcs8-4096.pem",
        "pkcs1/test_key_pkcs1-2048.pem",
        "pkcs1/test_key_pkcs1-4096.pem",
    })
    void loadPrivateKey_ShouldLoadKeyFromFile(String keyFilePath) throws Exception {
        // GIVEN
        var keyPath = Paths.get("./src/test/resources/keys", keyFilePath);

        // WHEN
        PrivateKey privateKey = KeyLoader.loadPrivateKey(keyPath);

        // THEN
        assertNotNull(privateKey.getEncoded());
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @ParameterizedTest
    @CsvSource({
        "pkcs8/test_key_pkcs8-2048.der",
        "pkcs8/test_key_pkcs8-4096.der",
        "pkcs8/test_key_pkcs8-2048.pem",
        "pkcs8/test_key_pkcs8-4096.pem",
        "pkcs1/test_key_pkcs1-2048.pem",
        "pkcs1/test_key_pkcs1-4096.pem",
    })
    void loadPrivateKey_ShouldLoadKeyFromStream(String keyFilePath) throws Exception {
        // GIVEN
        var keyStream = Files.newInputStream(Paths.get(String.format("./src/test/resources/keys/%s", keyFilePath)));

        // WHEN
        PrivateKey privateKey = KeyLoader.loadPrivateKey(keyStream);

        // THEN
        assertNotNull(privateKey.getEncoded());
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @Test
    void loadPrivateKey_ShouldLoadKeyFromPkcs12File() throws Exception {
        // GIVEN
        var keyPath = "./src/test/resources/keys/pkcs12/test_key.p12";
        var keyAlias = "mykeyalias";
        var keyPassword = "Password1";

        // WHEN
        PrivateKey privateKey = KeyLoader.loadPrivateKey(keyPath, keyAlias, keyPassword);

        // THEN
        assertNotNull(privateKey.getEncoded());
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @Test
    void loadPrivateKey_ShouldLoadKeyFromPkcs12Stream() throws Exception {
        // GIVEN
        var keyStream = Files.newInputStream(Paths.get("./src/test/resources/keys/pkcs12/test_key.p12"));
        var keyAlias = "mykeyalias";
        var keyPassword = "Password1";

        // WHEN
        PrivateKey privateKey = KeyLoader.loadPrivateKey(keyStream, keyAlias, keyPassword);

        // THEN
        assertNotNull(privateKey.getEncoded());
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @Test
    void loadPrivateKey_ShouldThrowIllegalArgumentException_WhenInvalidKey() {
        // GIVEN
        var invalidKeyPath = Paths.get("./src/test/resources/keys/pkcs8/test_invalid_key.der");

        // WHEN / THEN
        var ex = assertThrows(IllegalArgumentException.class, () -> KeyLoader.loadPrivateKey(invalidKeyPath));
        assertEquals("Unexpected key format!", ex.getMessage());
        assertInstanceOf(InvalidKeySpecException.class, ex.getCause());
    }

    @Test
    void loadPrivateKey_ShouldThrowNoSuchFileException_WhenKeyFileDoesNotExist() {
        // GIVEN
        var nonExistentKeyPath = Paths.get("./src/test/resources/some_file");

        // WHEN / THEN
        var ex = assertThrows(NoSuchFileException.class, () -> KeyLoader.loadPrivateKey(nonExistentKeyPath));
        assertTrue(ex.getMessage().contains("some_file"));
    }

    @ParameterizedTest
    @CsvSource({ "jwk/test_rsa.json, RSA", "jwk/test_ec.json, EC" })
    void loadKeyPair_ShouldLoadKeyPairFromFile(String keyFilePath, String expectedAlgorithm) throws Exception {
        // GIVEN
        var keyPath = Paths.get("./src/test/resources/keys", keyFilePath);

        // WHEN
        KeyPair keyPair = KeyLoader.loadKeyPair(keyPath);

        // THEN
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertEquals(expectedAlgorithm, keyPair.getPrivate().getAlgorithm());
    }

    @ParameterizedTest
    @CsvSource({ "jwk/test_rsa.json, RSA", "jwk/test_ec.json, EC" })
    void loadKeyPair_ShouldLoadKeyPairFromStream(String keyFilePath, String expectedAlgorithm) throws Exception {
        // GIVEN
        var keyStream = Files.newInputStream(Paths.get(String.format("./src/test/resources/keys/%s", keyFilePath)));

        // WHEN
        KeyPair keyPair = KeyLoader.loadKeyPair(keyStream);

        // THEN
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertEquals(expectedAlgorithm, keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void loadKeyPair_ShouldThrowNoSuchFileException_WhenJwkFileDoesNotExist() {
        // GIVEN
        var nonExistentJwkPath = Paths.get("./src/test/resources/some_file");

        // WHEN / THEN
        var ex = assertThrows(NoSuchFileException.class, () -> KeyLoader.loadKeyPair(nonExistentJwkPath));
        assertTrue(ex.getMessage().contains("some_file"));
    }
}
