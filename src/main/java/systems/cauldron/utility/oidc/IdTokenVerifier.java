package systems.cauldron.utility.oidc;

import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.Jwks;
import systems.cauldron.utility.jwt.Jwt;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;
import systems.cauldron.utility.jwt.jws.JwsVerifier;

import javax.json.JsonObject;
import java.net.URI;
import java.util.EnumSet;
import java.util.concurrent.CompletableFuture;

public class IdTokenVerifier {

    private final JwsVerifier verifier;
    private final EnumSet<JwsAlgorithm> keysForSigning;

    public IdTokenVerifier(JsonObject config) {
        URI jwksUri = URI.create(config.getString("jwks_uri"));
        Jwks jwks = new Jwks(jwksUri);
        this.verifier = new JwsVerifier(jwks);
        this.keysForSigning = EnumSet.noneOf(JwsAlgorithm.class);
        JsonUtility.streamArray(config, "id_token_signing_alg_values_supported")
                .map(JwsAlgorithm::fromString)
                .filter(a -> a != JwsAlgorithm.UNKNOWN)
                .forEach(keysForSigning::add);
    }

    public CompletableFuture<Void> refresh() {
        return verifier.refresh();
    }

    public boolean verify(String token) {
        Jwt jwt = Jwt.parse(token);
        if (jwt instanceof Jws jws) {
            if (!keysForSigning.contains(jws.algorithm())) {
                return false;
            }
            if (jws.algorithm() == JwsAlgorithm.NONE) {
                return false;
            }
            return verifier.verify(jws);
        } else {
            return false;
        }
    }
}
