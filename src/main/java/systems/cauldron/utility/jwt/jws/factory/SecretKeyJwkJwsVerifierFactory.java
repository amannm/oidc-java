package systems.cauldron.utility.jwt.jws.factory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

abstract class SecretKeyJwkJwsVerifierFactory extends JwkJwsVerifierFactory {

    protected static boolean verify(String algorithm, byte[] secretKey, byte[] header, byte[] payload, byte[] signature) {
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
}
