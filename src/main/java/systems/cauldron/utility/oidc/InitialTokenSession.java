package systems.cauldron.utility.oidc;

import systems.cauldron.utility.HttpUtility;
import systems.cauldron.utility.jwt.Jwt;
import systems.cauldron.utility.jwt.jws.Jws;

import javax.json.JsonObject;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class InitialTokenSession {

    private final URI authorizationEndpoint;
    private final URI tokenEndpoint;
    private final ClientConfig clientConfig;
    private final String state;
    private final String nonce;

    private final IdTokenVerifier verifier;

    private final AtomicReference<TokenState> tokenState;

    public InitialTokenSession(JsonObject config, ClientConfig clientConfig, IdTokenVerifier verifier) {
        this.authorizationEndpoint = URI.create(config.getString("authorization_endpoint"));
        this.tokenEndpoint = URI.create(config.getString("token_endpoint"));
        this.clientConfig = clientConfig;
        this.state = UUID.randomUUID().toString();
        this.nonce = UUID.randomUUID().toString();
        this.verifier = verifier;
        this.tokenState = new AtomicReference<>();
    }

    public String generateAuthorizationCodeRequestUri(Set<String> scopes) {
        return String.join("?", authorizationEndpoint.toString(), HttpUtility.urlEncode(Map.of(
                "response_type", "code",
                "client_id", clientConfig.clientId(),
                "scope", String.join(" ", scopes),
                "redirect_uri", clientConfig.redirectUri(),
                "state", state,
                "nonce", nonce
        )));
    }

    public CompletableFuture<Void> exchangeCodeForToken(String returnedCode, String returnedState) {
        if (state.equals(returnedState)) {
            throw new IllegalArgumentException("state mismatch");
        }
        return HttpUtility.postForJsonAsync(tokenEndpoint, Map.of(
                "code", returnedCode,
                "client_id", clientConfig.clientId(),
                "client_secret", clientConfig.clientSecret(),
                "redirect_uri", clientConfig.redirectUri(),
                "grant_type", "authorization_code"
        )).thenAccept(jsonObject -> {
            if (!"bearer".equalsIgnoreCase(jsonObject.getString("token_type"))) {
                throw new IllegalArgumentException("unexpected token type");
            }
            TokenState nextTokenState = new TokenState(
                    jsonObject.getString("access_token"),
                    Instant.now().minus(jsonObject.getJsonNumber("expires_in").longValue(), ChronoUnit.SECONDS),
                    jsonObject.containsKey("scope") ? Stream.of(jsonObject.getString("scope").split(" ")).collect(Collectors.toSet()) : Collections.emptySet(),
                    jsonObject.getString("id_token"),
                    jsonObject.containsKey("refresh_token") ? jsonObject.getString("refresh_token") : null
            );
            Jwt jwt = Jwt.parse(nextTokenState.idToken());
            if (jwt instanceof Jws jws) {
                JsonObject claims = verifier.verify(jws);
                if (!nonce.equals(claims.getString("nonce"))) {
                    throw new IllegalArgumentException("nonce mismatch");
                }
            } else {
                throw new IllegalArgumentException("identity token is not a JWS");
            }
            tokenState.set(nextTokenState);
        });
    }

    public Optional<String> getIdToken() {
        return Optional.ofNullable(tokenState.get())
                .map(TokenState::idToken);
    }
}
