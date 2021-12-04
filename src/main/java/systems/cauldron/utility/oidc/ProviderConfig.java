package systems.cauldron.utility.oidc;

import systems.cauldron.utility.HttpUtility;
import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.Jwks;
import systems.cauldron.utility.jwt.jws.JwksJwsVerifier;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.net.URI;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public record ProviderConfig(URI providerUri, JwksJwsVerifier verifier, Set<JwsAlgorithm> keysForSigning) {

    private static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

    public static CompletableFuture<ProviderConfig> create(URI providerUri) {
        URI configUri = URI.create(providerUri.toString() + OPENID_CONFIGURATION_PATH);
        return HttpUtility.getJsonAsync(configUri)
                .thenApply(config -> {
                    EnumSet<JwsAlgorithm> keysForSigning = EnumSet.noneOf(JwsAlgorithm.class);
                    JsonUtility.streamArray(config, "id_token_signing_alg_values_supported")
                            .map(JwsAlgorithm::fromString)
                            .filter(a -> a != JwsAlgorithm.UNKNOWN)
                            .filter(a -> a != JwsAlgorithm.NONE)
                            .forEach(keysForSigning::add);
                    URI jwksUri = URI.create(config.getString("jwks_uri"));
                    Jwks jwks = new Jwks(jwksUri);
                    JwksJwsVerifier verifier = new JwksJwsVerifier(jwks);
                    return new ProviderConfig(providerUri, verifier, keysForSigning);
                });
    }
}