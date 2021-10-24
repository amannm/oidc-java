package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

class HmacJwkJwsVerifierFactory extends SecretKeyJwkJwsVerifierFactory {

    @Override
    boolean validateShape(JsonObject jwk) {
        return jwk.containsKey("k");
    }

    @Override
    Collection<JwkJwsVerifier> build(JsonObject jwk) {
        byte[] key = Base64.getUrlDecoder().decode(jwk.getString("k"));
        if (key.length < 32) {
            throw new UnsupportedOperationException("HMAC key under 32 bytes: " + key.length);
        }
        if (jwk.containsKey("alg")) {
            String assertedAlg = jwk.getString("alg");
            JwkJwsVerifier verifier = switch (assertedAlg) {
                case "HS256" -> build(jwk, JwsAlgorithm.HS256, "HmacSHA256", key);
                case "HS384" -> build(jwk, JwsAlgorithm.HS384, "HmacSHA384", key);
                case "HS512" -> build(jwk, JwsAlgorithm.HS512, "HmacSHA512", key);
                default -> throw new UnsupportedOperationException("unsupported JWS algorithm: " + assertedAlg);
            };
            return Collections.singleton(verifier);
        } else {
            List<JwkJwsVerifier> results = new ArrayList<>();
            results.add(build(jwk, JwsAlgorithm.HS256, "HmacSHA256", key));
            if (key.length >= 48) {
                results.add(build(jwk, JwsAlgorithm.HS384, "HmacSHA384", key));
            }
            if (key.length >= 64) {
                results.add(build(jwk, JwsAlgorithm.HS512, "HmacSHA512", key));
            }
            return results;
        }
    }

    private static JwkJwsVerifier build(JsonObject jwk, JwsAlgorithm jwsAlgorithm, String jcaAlgorithm, byte[] key) {
        Optional<String> idResult = getKeyIdResult(jwk);
        return new JwkJwsVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return jwsAlgorithm;
            }

            @Override
            public String getKeyType() {
                return "oct";
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
                return SecretKeyJwkJwsVerifierFactory.verify(jcaAlgorithm, key, header, payload, signature);
            }
        };
    }
}
