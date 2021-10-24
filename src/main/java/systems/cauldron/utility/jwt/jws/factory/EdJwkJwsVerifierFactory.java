package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

class EdJwkJwsVerifierFactory extends PublicKeyJwkJwsVerifierFactory {

    @Override
    Collection<JwkJwsVerifier> build(JsonObject jwk) {
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
        return Collections.singleton(new JwkJwsVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return alg;
            }

            @Override
            public String getKeyType() {
                return "OKP";
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
                return EdJwkJwsVerifierFactory.verify(jcaCurve, publicKey, header, payload, signature);
            }
        });
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
}
