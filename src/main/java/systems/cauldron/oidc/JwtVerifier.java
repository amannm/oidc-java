package systems.cauldron.oidc;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;
import javax.json.JsonValue;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class JwtVerifier {

    private final JsonObject config;
    private final AtomicReference<Map<String, List<JsonObject>>> keys;
    private final Set<String> keysForSigning;

    public JwtVerifier(JsonObject config) {
        this.config = config;
        this.keys = new AtomicReference<>(Collections.emptyMap());
        this.keysForSigning = JsonUtility.streamArray(config, "id_token_signing_alg_values_supported")
                .collect(Collectors.toUnmodifiableSet());
    }

    public CompletableFuture<Void> update() {
        URI jwksUri = URI.create(config.getString("jwks_uri"));
        return HttpUtility.getJsonAsync(jwksUri)
                .thenAccept(jwksResponse -> keys.set(jwksResponse.getJsonArray("keys").stream()
                        .map(JsonValue::asJsonObject)
                        .collect(Collectors.groupingBy(JwtVerifier::computeAlgorithm))));
    }

    public boolean verify(String jwt) {
        String[] jwtParts = splitToken(jwt);
        JsonObject header = JsonUtility.readJson(jwtParts[0]);
        String alg = header.getString("alg");
        if (!keysForSigning.contains(alg)) {
            return false;
        }
        if ("none".equals(alg)) {
            return true;
        }
        return keys.get()
                .get(alg).stream()
                .filter(jwk -> {
                    boolean kidMatches = !header.containsKey("kid") || !jwk.containsKey("kid") || jwk.getString("kid").equals(header.getString("kid"));
                    boolean useMatches = !jwk.containsKey("use") || "sig".equals(jwk.getString("use"));
                    boolean keyOpsMatches = !jwk.containsKey("key_ops") || JsonUtility.streamArray(jwk, "key_ops").anyMatch("verify"::equals);
                    return kidMatches && useMatches && keyOpsMatches;
                })
                .anyMatch(jwk ->
                        switch (alg) {
                            case "HS256" -> verify(jwtParts, "HmacSHA256", getSecretKey(jwk));
                            case "HS384" -> verify(jwtParts, "HmacSHA384", getSecretKey(jwk));
                            case "HS512" -> verify(jwtParts, "HmacSHA512", getSecretKey(jwk));
                            case "RS256" -> verify(jwtParts, "SHA256withRSA", getRsaPublicKey(jwk));
                            case "RS384" -> verify(jwtParts, "SHA384withRSA", getRsaPublicKey(jwk));
                            case "RS512" -> verify(jwtParts, "SHA512withRSA", getRsaPublicKey(jwk));
                            case "ES256" -> verify(jwtParts, "SHA256withECDSA", 32, getEcPublicKey("secp256r1", jwk));
                            case "ES256K" -> verify(jwtParts, "SHA256withECDSA", 32, getEcPublicKey("secp256k1", jwk));
                            case "ES384" -> verify(jwtParts, "SHA384withECDSA", 48, getEcPublicKey("secp384r1", jwk));
                            case "ES512" -> verify(jwtParts, "SHA512withECDSA", 66, getEcPublicKey("secp521r1", jwk));
                            case "PS256" -> verify(jwtParts, "SHA256withRSAandMGF1", getRsaPublicKey(jwk));
                            case "PS384" -> verify(jwtParts, "SHA384withRSAandMGF1", getRsaPublicKey(jwk));
                            case "PS512" -> verify(jwtParts, "SHA512withRSAandMGF1", getRsaPublicKey(jwk));
                            case "EdDSA" -> {
                                int encodedSignatureLength = jwtParts[2].length();
                                yield switch (encodedSignatureLength) {
                                    case 86 -> verify(jwtParts, "Ed25519", getEdDsaPublicKey(jwk));
                                    case 19 -> verify(jwtParts, "Ed448", getEdDsaPublicKey(jwk));
                                    default -> false;
                                };
                            }
                            default -> false;
                        }
                );
    }

    private static boolean verify(String[] parts, String algorithm, PublicKey publicKey) {
        byte[] header = parts[0].getBytes(StandardCharsets.UTF_8);
        byte[] payload = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] signature = parts[2].getBytes(StandardCharsets.UTF_8);
        return verify(algorithm, publicKey, header, payload, signature);
    }

    private static boolean verify(String[] parts, String algorithm, RSAPublicKey publicKey) {
        byte[] header = parts[0].getBytes(StandardCharsets.UTF_8);
        byte[] payload = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] signature = parts[2].getBytes(StandardCharsets.UTF_8);
        return verify(algorithm, publicKey, header, payload, signature);
    }

    private static boolean verify(String[] parts, String algorithm, int componentSize, ECPublicKey publicKey) {
        byte[] header = parts[0].getBytes(StandardCharsets.UTF_8);
        byte[] payload = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] signature = convertJoseToDer(componentSize, parts[2].getBytes(StandardCharsets.UTF_8));
        return verify(algorithm, publicKey, header, payload, signature);
    }

    private static boolean verify(String algorithm, PublicKey publicKey, byte[] header, byte[] payload, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(header);
            verifier.update((byte) 46);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean verify(String[] parts, String algorithm, byte[] secretKey) {
        byte[] header = parts[0].getBytes(StandardCharsets.UTF_8);
        byte[] payload = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] signature = parts[2].getBytes(StandardCharsets.UTF_8);
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secretKey, algorithm));
            mac.update(header);
            mac.update((byte) 46);
            byte[] hmac = mac.doFinal(payload);
            return MessageDigest.isEqual(hmac, signature);
        } catch (Exception ex) {
            return false;
        }
    }


    private static String computeAlgorithm(JsonObject item) {
        if (item.containsKey("alg")) {
            return item.getString("alg");
        } else {
            String kty = item.getString("kty");
            return switch (kty) {
                case "RSA" -> {
                    int encodedModulusLength = item.getString("n").length();
                    yield switch (encodedModulusLength) {
                        case 342 -> "RS256";
                        case 512 -> "RS384";
                        case 683 -> "RS512";
                        default -> throw new UnsupportedOperationException("unsupported encoded RSA modulus size: " + encodedModulusLength);
                    };
                }
                case "EC" -> {
                    String crv = item.getString("crv");
                    yield switch (crv) {
                        case "P-256" -> "ES256";
                        case "secp256k1" -> "ES256K";
                        case "P-384" -> "ES384";
                        case "P-521" -> "ES512";
                        default -> throw new UnsupportedOperationException("unsupported EC curve: " + crv);
                    };
                }
                case "oct" -> {
                    int encodedKeyLength = item.getString("k").length();
                    yield switch (encodedKeyLength) {
                        case 43 -> "HS256";
                        case 64 -> "HS384";
                        case 86 -> "HS512";
                        default -> throw new UnsupportedOperationException("unsupported encoded HMAC size: " + encodedKeyLength);
                    };
                }
                case "OKP" -> {
                    String crv = item.getString("crv");
                    yield switch (crv) {
                        case "Ed25519", "Ed448" -> "EdDSA";
                        case "X25519", "X448" -> "ECDH-ES";
                        default -> throw new UnsupportedOperationException("unsupported OKP curve: " + crv);
                    };
                }
                default -> throw new UnsupportedOperationException("unsupported 'kty' value: " + kty);
            };
        }
    }

    private static RSAPublicKey getRsaPublicKey(JsonObject item) {
        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(item.getString("n")));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(item.getString("e")));
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException("invalid RSA public key", ex);
        }
    }

    private static PublicKey getEdDsaPublicKey(JsonObject item) {
        byte[] pk = Base64.getUrlDecoder().decode(item.getString("x"));
        boolean xOdd = false;
        int lastbyteInt = pk[pk.length - 1];
        if ((lastbyteInt & 255) >> 7 == 1) {
            xOdd = true;
        }
        pk[pk.length - 1] &= 127;
        for (int i = 0; i < pk.length / 2; i++) {
            int x = pk.length - i - 1;
            byte temp = pk[i];
            pk[i] = pk[x];
            pk[x] = temp;
        }
        BigInteger y = new BigInteger(1, pk);
        try {
            NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
            EdECPublicKeySpec keySpec = new EdECPublicKeySpec(paramSpec, new EdECPoint(xOdd, y));
            KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException("invalid EC public key", ex);
        }
    }

    private static ECPublicKey getEcPublicKey(String algorithm, JsonObject item) {
        BigInteger x = new BigInteger(Base64.getUrlDecoder().decode(item.getString("x")));
        BigInteger y = new BigInteger(Base64.getUrlDecoder().decode(item.getString("y")));
        ECPoint point = new ECPoint(x, y);
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(algorithm));
            ECParameterSpec parameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(point, parameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        } catch (InvalidParameterSpecException ex) {
            throw new IllegalArgumentException("invalid EC parameters", ex);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException("invalid EC public key", ex);
        }
    }

    private static byte[] getSecretKey(JsonObject jwk) {
        return Base64.getUrlDecoder().decode(jwk.getString("k"));
    }

    private static String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new RuntimeException("invalid number of token parts: " + parts.length);
        }
        return parts;
    }

    private static byte[] convertJoseToDer(int componentLength, byte[] joseSignature) {
        if (joseSignature.length != componentLength * 2) {
            throw new RuntimeException("invalid JOSE signature");
        }
        int rPadding = countPadding(joseSignature, 0, componentLength);
        int sPadding = countPadding(joseSignature, componentLength, joseSignature.length);
        int rLength = componentLength - rPadding;
        int sLength = componentLength - sPadding;
        int length = 2 + rLength + 2 + sLength;
        if (length > 255) {
            throw new RuntimeException("invalid JOSE signature");
        }
        final byte[] derSignature;
        int offset;
        if (length > 0x7f) {
            derSignature = new byte[3 + length];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            offset = 1;
        }
        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) (length & 0xff);
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) rLength;
        if (rPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, 0, derSignature, offset, componentLength);
            offset += componentLength;
        } else {
            int copyLength = Math.min(componentLength, rLength);
            System.arraycopy(joseSignature, rPadding, derSignature, offset, copyLength);
            offset += copyLength;
        }
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) sLength;
        if (sPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, componentLength, derSignature, offset, componentLength);
        } else {
            System.arraycopy(joseSignature, componentLength + sPadding, derSignature, offset, Math.min(componentLength, sLength));
        }
        return derSignature;
    }

    private static int countPadding(byte[] bytes, int fromIndex, int toIndex) {
        int padding = 0;
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
            padding++;
        }
        return (bytes[fromIndex + padding] & 0xff) > 0x7f ? padding - 1 : padding;
    }
}
