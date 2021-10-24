package systems.cauldron.utility.jwt.jws;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.Jwks;
import systems.cauldron.utility.jwt.jws.factory.JwkJwsVerifierFactories;

import javax.json.JsonObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

public class JwksJwsVerifier {

    private final static Logger LOG = LogManager.getLogger(JwksJwsVerifier.class);

    private final Jwks jwks;
    private final AtomicReference<Map<JwsAlgorithm, List<JwkJwsVerifier>>> verifiers;

    public JwksJwsVerifier(Jwks jwks) {
        this.jwks = jwks;
        this.verifiers = new AtomicReference<>(Collections.emptyMap());
    }

    public boolean verify(Jws jws) {
        JwsAlgorithm jwsAlgorithm = jws.algorithm();
        if (jwsAlgorithm == JwsAlgorithm.NONE) {
            return true;
        }
        if (jwsAlgorithm == JwsAlgorithm.UNKNOWN) {
            return false;
        }
        Map<JwsAlgorithm, List<JwkJwsVerifier>> currentVerifiers = verifiers.get();
        return currentVerifiers.get(jwsAlgorithm).stream()
                .filter(verifier -> jws.keyId() == null || verifier.getKeyId().isEmpty() || jws.keyId().equals(verifier.getKeyId().get()))
                .anyMatch(v -> v.verify(jws));
    }

    public CompletableFuture<Void> refresh() {
        return jwks.load()
                .thenAccept(this::rebuildVerifiers);
    }

    private void rebuildVerifiers(List<JsonObject> jwksContents) {
        EnumMap<JwsAlgorithm, List<JwkJwsVerifier>> next = new EnumMap<>(JwsAlgorithm.class);
        jwksContents.forEach(jwk -> {
            if (jwk.containsKey("use") && !"sig".equals(jwk.getString("use"))) {
                LOG.warn("{} -> skipped key: 'use' specified but not equal to 'sig'", jwks.location());
                return;
            }
            if (jwk.containsKey("key_ops") && JsonUtility.streamArray(jwk, "key_ops").noneMatch("verify"::equals)) {
                LOG.warn("{} -> skipped key: 'key_ops' specified without 'verify'", jwks.location());
                return;
            }
            if (jwk.containsKey("alg")) {
                String alg = jwk.getString("alg");
                JwsAlgorithm jwsAlgorithm = JwsAlgorithm.fromString(alg);
                if (jwsAlgorithm == JwsAlgorithm.UNKNOWN) {
                    LOG.warn("{} -> skipped key: asserted 'alg' is not a supported JWS algorithm", jwks.location());
                    return;
                }
            }
            JwkJwsVerifierFactories.process(jwk,
                    verifier -> {
                        next.computeIfAbsent(verifier.getAlgorithm(), x -> new ArrayList<>()).add(verifier);
                        LOG.info("{} -> registered {} key: alg={} kid={}", jwks.location(),
                                verifier.getKeyType(),
                                verifier.getAlgorithm(),
                                verifier.getKeyId().orElse("None"));
                    },
                    error -> {
                        LOG.warn("{} -> {}", jwks.location(),
                                error);
                    });
        });
        verifiers.set(next);
    }
}
