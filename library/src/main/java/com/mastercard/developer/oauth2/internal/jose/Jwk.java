package com.mastercard.developer.oauth2.internal.jose;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.internal.json.JsonProvider;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a JSON Web Key as defined in <a href="https://tools.ietf.org/html/rfc7517">RFC 7517</a>.
 */
public final class Jwk extends ConcurrentHashMap<String, String> {

    private Jwk() {
        // Static class
    }

    /**
     * Creates a JWK representation from a public key.
     */
    public static Jwk fromKey(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            var jwk = new Jwk();
            jwk.put("kty", "RSA");
            jwk.put("e", base64UrlUInt(rsa.getPublicExponent()));
            jwk.put("n", base64UrlUInt(rsa.getModulus()));
            return jwk;
        } else if (publicKey instanceof ECPublicKey ec) {
            var jwk = new Jwk();
            jwk.put("kty", "EC");
            jwk.put("crv", curveName(ec));
            ECParameterSpec params = ec.getParams();
            ECPoint affine = ec.getW();
            int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
            jwk.put("x", base64UrlEncode(toUnsigned(affine.getAffineX(), fieldSize)));
            jwk.put("y", base64UrlEncode(toUnsigned(affine.getAffineY(), fieldSize)));
            return jwk;
        }
        throw new IllegalArgumentException("Unsupported public key type: " + publicKey.getClass().getName());
    }

    /**
     * Parses a JWK from its JSON representation.
     */
    public static Jwk fromJson(String jwkJson) {
        try {
            var jwk = new Jwk();
            Map<String, Object> jsonMap = JsonProvider.getInstance().parse(jwkJson);
            jsonMap.keySet().forEach(fieldName -> jwk.put(fieldName, (String) jsonMap.get(fieldName)));
            String kty = jwk.get("kty");
            if (kty == null) {
                throw new OAuth2ClientException("Missing required JWK parameter: kty");
            }
            if ("RSA".equalsIgnoreCase(kty)) {
                if (jwk.get("n") == null || jwk.get("e") == null || jwk.get("d") == null) {
                    throw new OAuth2ClientException("Missing required RSA JWK parameters (n, e, d)");
                }
            } else if ("EC".equalsIgnoreCase(kty)) {
                if (jwk.get("crv") == null || jwk.get("x") == null || jwk.get("y") == null || jwk.get("d") == null) {
                    throw new OAuth2ClientException("Missing required EC JWK parameters (crv, x, y, d)");
                }
            } else {
                throw new OAuth2ClientException("Unsupported key type: " + kty);
            }
            return jwk;
        } catch (OAuth2ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2ClientException("Unable to parse JWK JSON", e);
        }
    }

    /**
     * Converts this JWK to a key pair.
     */
    public KeyPair toKeyPair() {
        try {
            String kty = get("kty");
            if ("RSA".equalsIgnoreCase(kty)) {
                String nStr = get("n");
                String eStr = get("e");
                String dStr = get("d");
                if (nStr == null || eStr == null || dStr == null) {
                    throw new OAuth2ClientException("Missing required RSA JWK parameters (n,e,d)");
                }
                Base64.Decoder urlDecoder = Base64.getUrlDecoder();
                var n = new BigInteger(1, urlDecoder.decode(nStr));
                var e = new BigInteger(1, urlDecoder.decode(eStr));
                var d = new BigInteger(1, urlDecoder.decode(dStr));

                var kf = KeyFactory.getInstance("RSA");
                var pubSpec = new RSAPublicKeySpec(n, e);
                var privSpec = new RSAPrivateKeySpec(n, d);
                return new KeyPair(kf.generatePublic(pubSpec), kf.generatePrivate(privSpec));
            } else if ("EC".equalsIgnoreCase(kty)) {
                String crv = get("crv");
                String xStr = get("x");
                String yStr = get("y");
                String dStr = get("d");
                if (crv == null || xStr == null || yStr == null || dStr == null) {
                    throw new OAuth2ClientException("Missing required EC JWK parameters (crv,x,y,d)");
                }
                if (!"P-256".equalsIgnoreCase(crv)) {
                    throw new IllegalStateException("Unsupported curve: " + crv);
                }
                Base64.Decoder urlDecoder = Base64.getUrlDecoder();
                var x = new BigInteger(1, urlDecoder.decode(xStr));
                var y = new BigInteger(1, urlDecoder.decode(yStr));
                var d = new BigInteger(1, urlDecoder.decode(dStr));

                // Obtain EC parameters for secp256r1 (a.k.a. P-256)
                var params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec("secp256r1"));
                ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

                var kf = KeyFactory.getInstance("EC");
                var w = new ECPoint(x, y);
                var pubSpec = new ECPublicKeySpec(w, ecSpec);
                var privSpec = new ECPrivateKeySpec(d, ecSpec);
                return new KeyPair(kf.generatePublic(pubSpec), kf.generatePrivate(privSpec));
            } else {
                throw new IllegalStateException("Unsupported key type: " + kty);
            }
        } catch (Exception e) {
            throw new OAuth2ClientException("Unable to construct key pair from JWK", e);
        }
    }

    /**
     * Computes the JWK thumbprint as defined by <a href="https://tools.ietf.org/html/rfc7638">RFC 7638</a>.
     * The thumbprint is an SHA-256 hash of the canonical JSON representation of the JWK.
     */
    public String computeThumbprint() {
        String kty = get("kty");
        String canonical;
        if ("RSA".equals(kty)) {
            // Order: e, kty, n
            String e = get("e");
            String n = get("n");
            canonical = """
            {"e":"%s","kty":"RSA","n":"%s"}
            """
                .formatted(e, n)
                .strip();
        } else if ("EC".equals(kty)) {
            // Order: crv, kty, x, y
            String crv = get("crv");
            String x = get("x");
            String y = get("y");
            canonical = """
            {"crv":"%s","kty":"EC","x":"%s","y":"%s"}
            """
                .formatted(crv, x, y)
                .strip();
        } else {
            throw new IllegalStateException("Unsupported key type: " + kty);
        }

        try {
            var messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new OAuth2ClientException("Unable to compute JWK thumbprint", e);
        }
    }

    private static String curveName(ECPublicKey ec) {
        int bits = ec.getParams().getCurve().getField().getFieldSize();
        if (bits <= 256) return "P-256";
        else throw new IllegalStateException("Unsupported curve size: " + bits);
    }

    private static String base64UrlUInt(BigInteger i) {
        return base64UrlEncode(toUnsigned(i));
    }

    private static String base64UrlEncode(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] toUnsigned(BigInteger i) {
        byte[] bytes = i.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static byte[] toUnsigned(BigInteger i, int size) {
        byte[] raw = toUnsigned(i);
        if (raw.length == size) return raw;
        byte[] out = new byte[size];
        System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        return out;
    }
}
