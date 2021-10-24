package systems.cauldron.utility.jwt.jws.factory;

import systems.cauldron.utility.jwt.jws.JwkJwsVerifier;

import javax.json.JsonObject;
import java.util.function.Consumer;

public class JwkJwsVerifiers {

    private static final JwkJwsVerifierFactory RSA = new RsaJwkJwsVerifierFactory();
    private static final JwkJwsVerifierFactory EC = new EcJwkJwsVerifierFactory();
    private static final JwkJwsVerifierFactory HMAC = new HmacJwkJwsVerifierFactory();
    private static final JwkJwsVerifierFactory Ed = new EdJwkJwsVerifierFactory();

    public static void process(JsonObject jwk, Consumer<JwkJwsVerifier> onBuild, Consumer<String> onError) {
        String kty = jwk.getString("kty");
        switch (kty) {
            case "RSA" -> {
                boolean validShape = jwk.containsKey("n") && jwk.containsKey("e") && !jwk.containsKey("d");
                processKeyType(kty, jwk, validShape, JwkJwsVerifiers.RSA, onBuild, onError);
            }
            case "EC" -> {
                boolean validShape = jwk.containsKey("crv") && jwk.containsKey("x") && jwk.containsKey("y") && !jwk.containsKey("d");
                processKeyType(kty, jwk, validShape, JwkJwsVerifiers.EC, onBuild, onError);
            }
            case "oct" -> {
                boolean validShape = jwk.containsKey("k");
                processKeyType(kty, jwk, validShape, JwkJwsVerifiers.HMAC, onBuild, onError);
            }
            case "OKP" -> {
                boolean validShape = jwk.containsKey("crv") && jwk.containsKey("x") && !jwk.containsKey("d");
                processKeyType(kty, jwk, validShape, JwkJwsVerifiers.Ed, onBuild, onError);
            }
            default -> onError.accept(String.format("unknown family: %s", kty));
        }
    }

    private static void processKeyType(String kty,
                                       JsonObject jwk,
                                       boolean validShape,
                                       JwkJwsVerifierFactory verifierFactory,
                                       Consumer<JwkJwsVerifier> onBuild,
                                       Consumer<String> onError) {
        if (validShape) {
            try {
                verifierFactory.build(jwk).forEach(onBuild);
            } catch (Exception ex) {
                onError.accept(String.format("%s key: %s", kty, ex.getMessage()));
            }
        } else {
            onError.accept(String.format("%s key: invalid shape", kty));
        }
    }
}
