package systems.cauldron.utility.jwt.jws.factory;

import java.security.PublicKey;
import java.security.Signature;

abstract class PublicKeyJwkJwsVerifierFactory extends JwkJwsVerifierFactory {

    protected static boolean verify(String algorithm, PublicKey publicKey, byte[] header, byte[] payload, byte[] signature) {
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
}
