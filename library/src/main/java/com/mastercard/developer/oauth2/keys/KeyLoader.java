package com.mastercard.developer.oauth2.keys;

import com.mastercard.developer.oauth2.internal.jose.Jwk;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading keys.
 */
public final class KeyLoader {

    private static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
    private static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----";

    private KeyLoader() {
        // Utility class
    }

    /**
     * Loads a private key from a file.
     * Supports PKCS1 PEM, PKCS8 PEM, and PKCS8 DER formats.
     */
    public static PrivateKey loadPrivateKey(Path keyFilePath) throws GeneralSecurityException, IOException {
        var keyStream = new ByteArrayInputStream(Files.readAllBytes(keyFilePath));
        return loadPrivateKey(keyStream);
    }

    /**
     * Loads a private key from an input stream.
     * Supports PKCS1 PEM, PKCS8 PEM, and PKCS8 DER formats.
     */
    public static PrivateKey loadPrivateKey(InputStream keyDataStream) throws GeneralSecurityException, IOException {
        byte[] keyBytes = keyDataStream.readAllBytes();
        var keyDataString = new String(keyBytes, StandardCharsets.UTF_8);

        if (keyDataString.contains(PKCS_1_PEM_HEADER)) {
            // OpenSSL / PKCS#1 Base64 PEM encoded file
            keyDataString = keyDataString.replace(PKCS_1_PEM_HEADER, "");
            keyDataString = keyDataString.replace(PKCS_1_PEM_FOOTER, "");
            keyDataString = keyDataString.replace("\n", "");
            keyDataString = keyDataString.replace("\r", "");
            return readPkcs1PrivateKey(Base64.getDecoder().decode(keyDataString));
        }

        if (keyDataString.contains(PKCS_8_PEM_HEADER)) {
            // PKCS#8 Base64 PEM encoded file
            keyDataString = keyDataString.replace(PKCS_8_PEM_HEADER, "");
            keyDataString = keyDataString.replace(PKCS_8_PEM_FOOTER, "");
            keyDataString = keyDataString.replace("\n", "");
            keyDataString = keyDataString.replace("\r", "");
            return readPkcs8PrivateKey(Base64.getDecoder().decode(keyDataString));
        }

        // We assume it's a PKCS#8 DER encoded binary file
        return readPkcs8PrivateKey(keyBytes);
    }

    /**
     * Loads a private key from a PKCS12 keystore file.
     */
    public static PrivateKey loadPrivateKey(String pkcs12KeyFilePath, String decryptionKeyAlias, String decryptionKeyPassword) throws GeneralSecurityException, IOException {
        var pkcs12KeyStore = KeyStore.getInstance("PKCS12");
        pkcs12KeyStore.load(Files.newInputStream(Paths.get(pkcs12KeyFilePath)), decryptionKeyPassword.toCharArray());
        return (PrivateKey) pkcs12KeyStore.getKey(decryptionKeyAlias, decryptionKeyPassword.toCharArray());
    }

    /**
     * Loads a private key from a PKCS12 keystore input stream.
     */
    public static PrivateKey loadPrivateKey(InputStream pkcs12KeyInputStream, String signingKeyAlias, String signingKeyPassword)
        throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var pkcs12KeyStore = KeyStore.getInstance("PKCS12");
        pkcs12KeyStore.load(pkcs12KeyInputStream, signingKeyPassword.toCharArray());
        return (PrivateKey) pkcs12KeyStore.getKey(signingKeyAlias, signingKeyPassword.toCharArray());
    }

    /**
     * Loads a key pair from a JWK file.
     */
    public static KeyPair loadKeyPair(Path jwkFilePath) throws IOException {
        var keyStream = new ByteArrayInputStream(Files.readAllBytes(jwkFilePath));
        return loadKeyPair(keyStream);
    }

    /**
     * Loads a key pair from a JWK input stream.
     */
    public static KeyPair loadKeyPair(InputStream jwkInputStream) throws IOException {
        byte[] keyBytes = jwkInputStream.readAllBytes();
        var jwk = Jwk.fromJson(new String(keyBytes, StandardCharsets.UTF_8));
        return jwk.toKeyPair();
    }

    private static PrivateKey readPkcs8PrivateKey(byte[] pkcs8Bytes) throws GeneralSecurityException {
        var keyFactory = KeyFactory.getInstance("RSA");
        var keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unexpected key format!", e);
        }
    }

    private static PrivateKey readPkcs1PrivateKey(byte[] pkcs1Bytes) throws GeneralSecurityException {
        // We can't use Java internal APIs to parse ASN.1 structures, so we build a PKCS#8 key Java can understand
        int pkcs1Length = pkcs1Bytes.length;
        int totalLength = pkcs1Length + 22;
        var pkcs8Header = new byte[] {
            0x30,
            (byte) 0x82,
            (byte) ((totalLength >> 8) & 0xff),
            (byte) (totalLength & 0xff), // Sequence + total length
            0x2,
            0x1,
            0x0, // Integer (0)
            0x30,
            0xD,
            0x6,
            0x9,
            0x2A,
            (byte) 0x86,
            0x48,
            (byte) 0x86,
            (byte) 0xF7,
            0xD,
            0x1,
            0x1,
            0x1,
            0x5,
            0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
            0x4,
            (byte) 0x82,
            (byte) ((pkcs1Length >> 8) & 0xff),
            (byte) (pkcs1Length & 0xff), // Octet string + length
        };
        byte[] pkcs8bytes = concat(pkcs8Header, pkcs1Bytes);
        return readPkcs8PrivateKey(pkcs8bytes);
    }

    private static byte[] concat(byte[] array1, byte[] array2) {
        return ByteBuffer.allocate(array1.length + array2.length)
            .put(array1)
            .put(array2)
            .array();
    }
}
