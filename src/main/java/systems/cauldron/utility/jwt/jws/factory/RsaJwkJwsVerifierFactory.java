package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

class RsaJwkJwsVerifierFactory extends PublicKeyJwkJwsVerifierFactory {

    @Override
    Collection<JwkJwsVerifier> build(JsonObject jwk) {
        byte[] modulus = Base64.getUrlDecoder().decode(jwk.getString("n"));
        byte[] exponent = Base64.getUrlDecoder().decode(jwk.getString("e"));
        if (modulus.length < 256) {
            throw new UnsupportedOperationException("RSA key under 256 bytes: " + modulus.length);
        }
        if (jwk.containsKey("alg")) {
            String assertedAlg = jwk.getString("alg");
            switch (assertedAlg) {
                case "RS256" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.RS256, "SHA256withRSA", modulus, exponent));
                }
                case "RS384" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.RS384, "SHA384withRSA", modulus, exponent));
                }
                case "RS512" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.RS512, "SHA512withRSA", modulus, exponent));
                }
                case "PS256" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.PS256, "SHA256withRSA", modulus, exponent));
                }
                case "PS384" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.PS384, "SHA384withRSA", modulus, exponent));
                }
                case "PS512" -> {
                    return Collections.singleton(build(jwk, JwsAlgorithm.PS512, "SHA512withRSA", modulus, exponent));
                }
                default -> {
                    throw new UnsupportedOperationException("unsupported JWS algorithm: " + assertedAlg);
                }
            }
        } else {
            return List.of(
                    build(jwk, JwsAlgorithm.RS256, "SHA256withRSA", modulus, exponent),
                    build(jwk, JwsAlgorithm.RS384, "SHA384withRSA", modulus, exponent),
                    build(jwk, JwsAlgorithm.RS512, "SHA512withRSA", modulus, exponent),
                    build(jwk, JwsAlgorithm.PS256, "SHA256withRSAandMGF1", modulus, exponent),
                    build(jwk, JwsAlgorithm.PS384, "SHA384withRSAandMGF1", modulus, exponent),
                    build(jwk, JwsAlgorithm.PS512, "SHA512withRSAandMGF1", modulus, exponent)
            );
        }
    }

    private static JwkJwsVerifier build(JsonObject jwk, JwsAlgorithm algorithm, String jcaAlgorithm, byte[] modulus, byte[] exponent) {
        RSAPublicKey publicKey = getRsaPublicKey(modulus, exponent);
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwkJwsVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return algorithm;
            }

            @Override
            public String getKeyType() {
                return "RSA";
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
                return RsaJwkJwsVerifierFactory.verify(jcaAlgorithm, publicKey, header, payload, signature);
            }
        };
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
}
