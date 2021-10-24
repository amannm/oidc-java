package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;

import javax.json.JsonObject;
import java.util.Collection;
import java.util.Optional;

abstract class JwkJwsVerifierFactory {

    abstract boolean validateShape(JsonObject jwk);

    abstract Collection<JwkJwsVerifier> build(JsonObject jwk);

    protected static Optional<String> getKeyIdResult(JsonObject jwk) {
        return jwk.containsKey("kid") ? Optional.of(jwk.getString("kid")) : Optional.empty();
    }
}
