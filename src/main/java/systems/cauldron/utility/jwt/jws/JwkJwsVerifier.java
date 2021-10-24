package systems.cauldron.utility.jwt.jws;

import java.util.Optional;

public interface JwkJwsVerifier {
    JwsAlgorithm getAlgorithm();

    String getKeyType();

    Optional<String> getKeyId();

    boolean verify(Jws jws);
}
