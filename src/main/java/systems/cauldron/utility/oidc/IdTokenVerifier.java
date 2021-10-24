package systems.cauldron.utility.oidc;

import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.Jwks;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;
import systems.cauldron.utility.jwt.jws.JwsVerifier;

import javax.json.JsonObject;
import java.net.URI;
import java.time.Instant;
import java.util.EnumSet;
import java.util.concurrent.CompletableFuture;

public class IdTokenVerifier {

    private final String clientId;
    private final JsonObject config;
    private final JwsVerifier verifier;
    private final EnumSet<JwsAlgorithm> keysForSigning;

    public IdTokenVerifier(JsonObject config, String clientId) {
        this.clientId = clientId;
        this.config = config;
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

    public JsonObject verify(Jws jws) {
        if (!keysForSigning.contains(jws.algorithm())) {
            throw new IllegalArgumentException("JWS algorithm not supported for signing");
        }
        if (jws.algorithm() == JwsAlgorithm.NONE) {
            throw new IllegalArgumentException("JWS algorithm cannot be 'none'");
        }
        if (!verifier.verify(jws)) {
            throw new IllegalArgumentException("JWS signature verification failure");
        }
        JsonObject claims = JsonUtility.readJson(jws.payload());
        if (!config.getString("issuer").equals(claims.getString("iss"))) {
            throw new IllegalArgumentException("issuer mismatch");
        }
        if (!clientId.equals(claims.getString("aud"))) {
            throw new IllegalArgumentException("audience mismatch");
        }
        Instant expiration = Instant.ofEpochSecond(claims.getJsonNumber("exp").longValue());
        if (!Instant.now().isBefore(expiration)) {
            throw new IllegalArgumentException("token expired");
        }
        return claims;
    }
}
