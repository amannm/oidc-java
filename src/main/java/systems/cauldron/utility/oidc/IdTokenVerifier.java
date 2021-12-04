package systems.cauldron.utility.oidc;

import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

public class IdTokenVerifier {

    private final String clientId;
    private final ProviderConfig config;

    public IdTokenVerifier(String clientId, ProviderConfig config) {
        this.clientId = clientId;
        this.config = config;
    }

    public JsonObject verify(Jws jws) {
        if (!config.keysForSigning().contains(jws.algorithm())) {
            throw new IllegalArgumentException("JWS algorithm not supported for signing");
        }
        if (!config.verifier().verify(jws)) {
            throw new IllegalArgumentException("JWS signature verification failure");
        }
        JsonObject claims = JsonUtility.readJson(jws.payload());
        if (!config.providerUri().toString().equals(claims.getString("iss"))) {
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
