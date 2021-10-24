package systems.cauldron.utility.jwt.jws;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

class JwsJwkVerifierFactory {

    private static JwsJwkVerifier buildHmacVerifier(JsonObject jwk, JwsAlgorithm jwsAlgorithm, String jcaAlgorithm, byte[] key) {
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwsJwkVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return jwsAlgorithm;
            }

            @Override
            public Optional<String> getKeyId() {
                return idResult;
            }

            @Override
            public boolean verify(Jws jws) {
                byte[] header = jws.header();
                byte[] payload = jws.payload();
                byte[] signature = jws.signature();
                return JwsJwkVerifierFactory.verify(jcaAlgorithm, key, header, payload, signature);
            }
        };
    }

    static Collection<JwsJwkVerifier> buildHmacVerifiers(JsonObject jwk) {
        byte[] key = Base64.getUrlDecoder().decode(jwk.getString("k"));
        if (key.length < 32) {
            throw new UnsupportedOperationException("HMAC key under 32 bytes: " + key.length);
        }
        if (jwk.containsKey("alg")) {
            String assertedAlg = jwk.getString("alg");
            switch (assertedAlg) {
                case "HS256" -> {
                    return List.of(buildHmacVerifier(jwk, JwsAlgorithm.HS256, "HmacSHA256", key));
                }
                case "HS384" -> {
                    return List.of(buildHmacVerifier(jwk, JwsAlgorithm.HS384, "HmacSHA384", key));
                }
                case "HS512" -> {
                    return List.of(buildHmacVerifier(jwk, JwsAlgorithm.HS512, "HmacSHA512", key));
                }
                default -> {
                    throw new UnsupportedOperationException("unsupported JWS algorithm: " + assertedAlg);
                }
            }
        } else {
            List<JwsJwkVerifier> results = new ArrayList<>();
            results.add(buildHmacVerifier(jwk, JwsAlgorithm.HS256, "HmacSHA256", key));
            if (key.length >= 48) {
                results.add(buildHmacVerifier(jwk, JwsAlgorithm.HS384, "HmacSHA384", key));
            }
            if (key.length >= 64) {
                results.add(buildHmacVerifier(jwk, JwsAlgorithm.HS512, "HmacSHA512", key));
            }
            return results;
        }
    }

    private static JwsJwkVerifier buildRsaVerifier(JsonObject jwk, JwsAlgorithm algorithm, String jcaAlgorithm, byte[] modulus, byte[] exponent) {
        RSAPublicKey publicKey = getRsaPublicKey(modulus, exponent);
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwsJwkVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return algorithm;
            }

            @Override
            public Optional<String> getKeyId() {
                return idResult;
            }

            @Override
            public boolean verify(Jws jws) {
                byte[] header = jws.header();
                byte[] payload = jws.payload();
                byte[] signature = jws.signature();
                return JwsJwkVerifierFactory.verify(jcaAlgorithm, publicKey, header, payload, signature);
            }
        };
    }

    static Collection<JwsJwkVerifier> buildRsaVerifiers(JsonObject jwk) {
        byte[] modulus = Base64.getUrlDecoder().decode(jwk.getString("n"));
        byte[] exponent = Base64.getUrlDecoder().decode(jwk.getString("e"));
        if (modulus.length < 256) {
            throw new UnsupportedOperationException("RSA key under 256 bytes: " + modulus.length);
        }
        if (jwk.containsKey("alg")) {
            String assertedAlg = jwk.getString("alg");
            switch (assertedAlg) {
                case "RS256" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.RS256, "SHA256withRSA", modulus, exponent));
                }
                case "RS384" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.RS384, "SHA384withRSA", modulus, exponent));
                }
                case "RS512" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.RS512, "SHA512withRSA", modulus, exponent));
                }
                case "PS256" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.PS256, "SHA256withRSA", modulus, exponent));
                }
                case "PS384" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.PS384, "SHA384withRSA", modulus, exponent));
                }
                case "PS512" -> {
                    return Collections.singleton(buildRsaVerifier(jwk, JwsAlgorithm.PS512, "SHA512withRSA", modulus, exponent));
                }
                default -> {
                    throw new UnsupportedOperationException("unsupported JWS algorithm: " + assertedAlg);
                }
            }
        } else {
            return List.of(
                    buildRsaVerifier(jwk, JwsAlgorithm.RS256, "SHA256withRSA", modulus, exponent),
                    buildRsaVerifier(jwk, JwsAlgorithm.RS384, "SHA384withRSA", modulus, exponent),
                    buildRsaVerifier(jwk, JwsAlgorithm.RS512, "SHA512withRSA", modulus, exponent),
                    buildRsaVerifier(jwk, JwsAlgorithm.PS256, "SHA256withRSAandMGF1", modulus, exponent),
                    buildRsaVerifier(jwk, JwsAlgorithm.PS384, "SHA384withRSAandMGF1", modulus, exponent),
                    buildRsaVerifier(jwk, JwsAlgorithm.PS512, "SHA512withRSAandMGF1", modulus, exponent)
            );
        }
    }

    static JwsJwkVerifier buildEcVerifier(JsonObject jwk) {
        String crv = jwk.getString("crv");
        byte[] x = Base64.getUrlDecoder().decode(jwk.getString("x"));
        byte[] y = Base64.getUrlDecoder().decode(jwk.getString("y"));
        JwsAlgorithm alg;
        String jcaCurve;
        int componentSize;
        switch (crv) {
            case "P-256" -> {
                alg = JwsAlgorithm.ES256;
                jcaCurve = "secp256r1";
                componentSize = 32;
            }
            case "secp256k1" -> {
                alg = JwsAlgorithm.ES256K;
                jcaCurve = "secp256k1";
                componentSize = 32;
            }
            case "P-384" -> {
                alg = JwsAlgorithm.ES384;
                jcaCurve = "secp384r1";
                componentSize = 48;
            }
            case "P-521" -> {
                alg = JwsAlgorithm.ES512;
                jcaCurve = "secp521r1";
                componentSize = 66;
            }
            default -> {
                throw new UnsupportedOperationException("unsupported curve: " + crv);
            }
        }
        ECPublicKey publicKey = getEcPublicKey(jcaCurve, x, y);
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwsJwkVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return alg;
            }

            @Override
            public Optional<String> getKeyId() {
                return idResult;
            }

            @Override
            public boolean verify(Jws jws) {
                byte[] header = jws.header();
                byte[] payload = jws.payload();
                byte[] signature = jws.signature();
                byte[] derSignature = convertJoseToDer(componentSize, signature);
                return JwsJwkVerifierFactory.verify(jcaCurve, publicKey, header, payload, derSignature);
            }
        };
    }

    static JwsJwkVerifier buildEdEcVerifier(JsonObject jwk) {
        String crv = jwk.getString("crv");
        byte[] x = Base64.getUrlDecoder().decode(jwk.getString("x"));
        JwsAlgorithm alg;
        String jcaCurve;
        switch (crv) {
            case "Ed25519" -> {
                alg = JwsAlgorithm.EDDSA;
                jcaCurve = "Ed25519";
            }
            case "Ed448" -> {
                alg = JwsAlgorithm.EDDSA;
                jcaCurve = "Ed448";
            }
            default -> {
                throw new UnsupportedOperationException("unsupported curve: " + crv);
            }
        }
        EdECPublicKey publicKey = getEdEcPublicKey(jcaCurve, x);
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwsJwkVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return alg;
            }

            @Override
            public Optional<String> getKeyId() {
                return idResult;
            }

            @Override
            public boolean verify(Jws jws) {
                byte[] header = jws.header();
                byte[] payload = jws.payload();
                byte[] signature = jws.signature();
                return JwsJwkVerifierFactory.verify(jcaCurve, publicKey, header, payload, signature);
            }
        };
    }

    private static Optional<String> getKeyIdResult(JsonObject jwk) {
        return jwk.containsKey("kid") ? Optional.of(jwk.getString("kid")) : Optional.empty();
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

    private static boolean verify(String algorithm, byte[] secretKey, byte[] header, byte[] payload, byte[] signature) {
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

    private static RSAPublicKey getRsaPublicKey(byte[] rawModulus, byte[] rawExponent) {
        BigInteger modulus = new BigInteger(1, rawModulus);
        BigInteger exponent = new BigInteger(1, rawExponent);
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

    private static EdECPublicKey getEdEcPublicKey(String curve, byte[] rawPublicKey) {
        boolean xOdd = (rawPublicKey[rawPublicKey.length - 1] & 255) >> 7 == 1;
        rawPublicKey[rawPublicKey.length - 1] &= 127;
        for (int i = 0; i < rawPublicKey.length / 2; i++) {
            int j = rawPublicKey.length - i - 1;
            byte temp = rawPublicKey[i];
            rawPublicKey[i] = rawPublicKey[j];
            rawPublicKey[j] = temp;
        }
        BigInteger y = new BigInteger(1, rawPublicKey);
        EdECPoint point = new EdECPoint(xOdd, y);
        try {
            NamedParameterSpec paramSpec = new NamedParameterSpec(curve);
            EdECPublicKeySpec keySpec = new EdECPublicKeySpec(paramSpec, point);
            KeyFactory keyFactory = KeyFactory.getInstance(curve);
            return (EdECPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException("invalid EdEC public key", ex);
        }
    }

    private static ECPublicKey getEcPublicKey(String curve, byte[] rawX, byte[] rawY) {
        BigInteger x = new BigInteger(rawX);
        BigInteger y = new BigInteger(rawY);
        ECPoint point = new ECPoint(x, y);
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curve));
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
            derSignature[0] = (byte) 0x30;
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            derSignature[0] = (byte) 0x30;
            offset = 1;
        }
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
