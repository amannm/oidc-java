package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

class EcJwkJwsVerifierFactory extends PublicKeyJwkJwsVerifierFactory {

    @Override
    Collection<JwkJwsVerifier> build(JsonObject jwk) {
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
        return Collections.singleton(new JwkJwsVerifier() {
            @Override
            public JwsAlgorithm getAlgorithm() {
                return alg;
            }

            @Override
            public String getKeyType() {
                return "EC";
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
                return EcJwkJwsVerifierFactory.verify(jcaCurve, publicKey, header, payload, derSignature);
            }
        });
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
