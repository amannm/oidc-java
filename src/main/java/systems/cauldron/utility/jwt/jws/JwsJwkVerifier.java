package systems.cauldron.utility.jwt.jws;

import java.util.Optional;

interface JwsJwkVerifier {
    JwsAlgorithm getAlgorithm();

    Optional<String> getKeyId();

    boolean verify(Jws jws);
}
