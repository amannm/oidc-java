package systems.cauldron.utility.jwt.jws;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.Jwks;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

public class JwsVerifier {

    private final static Logger LOG = LogManager.getLogger(JwsVerifier.class);

    private final Jwks jwks;
    private final AtomicReference<Map<JwsAlgorithm, List<JwsJwkVerifier>>> jwsJwkVerifiers;


    public JwsVerifier(Jwks jwks) {
        this.jwks = jwks;
        this.jwsJwkVerifiers = new AtomicReference<>(Collections.emptyMap());
    }

    public CompletableFuture<Void> refresh() {
        return jwks.load()
                .thenAccept(jwksResponse -> {
                    EnumMap<JwsAlgorithm, List<JwsJwkVerifier>> next = new EnumMap<>(JwsAlgorithm.class);
                    jwksResponse.forEach(jwk -> {
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
                        String kty = jwk.getString("kty");
                        switch (kty) {
                            case "RSA" -> {
                                if (jwk.containsKey("n") && jwk.containsKey("e") && !jwk.containsKey("d")) {
                                    try {
                                        JwsJwkVerifierFactory.buildRsaVerifiers(jwk).forEach(v -> {
                                            next.computeIfAbsent(v.getAlgorithm(), x -> new ArrayList<>()).add(v);
                                            LOG.info("{} -> registered {} key: alg={} kid={}", jwks.location(), kty, v.getAlgorithm(), v.getKeyId().orElse("None"));
                                        });
                                    } catch (Exception ex) {
                                        LOG.warn("{} -> skipped {} key: {}", jwks.location(), kty, ex.getMessage());
                                    }
                                } else {
                                    LOG.warn("{} -> skipped {} key: invalid shape", jwks.location(), kty);
                                }
                            }
                            case "EC" -> {
                                if (jwk.containsKey("crv") && jwk.containsKey("x") && jwk.containsKey("y") && !jwk.containsKey("d")) {
                                    try {
                                        JwsJwkVerifier v = JwsJwkVerifierFactory.buildEcVerifier(jwk);
                                        next.computeIfAbsent(v.getAlgorithm(), x -> new ArrayList<>()).add(v);
                                        LOG.info("{} -> registered {} key: alg={} kid={}", jwks.location(), kty, v.getAlgorithm(), v.getKeyId().orElse("None"));
                                    } catch (Exception ex) {
                                        LOG.warn("{} -> skipped {} key: {}", jwks.location(), kty, ex.getMessage());
                                    }
                                } else {
                                    LOG.warn("{} -> skipped {} key: invalid shape", kty, jwks.location());
                                }

                            }
                            case "oct" -> {
                                if (jwk.containsKey("k")) {
                                    try {
                                        JwsJwkVerifierFactory.buildHmacVerifiers(jwk).forEach(v -> {
                                            next.computeIfAbsent(v.getAlgorithm(), x -> new ArrayList<>()).add(v);
                                            LOG.info("{} -> registered {} key: alg={} kid={}", jwks.location(), kty, v.getAlgorithm(), v.getKeyId().orElse("None"));
                                        });
                                    } catch (Exception ex) {
                                        LOG.warn("{} -> skipped {} key: {}", jwks.location(), kty, ex.getMessage());
                                    }
                                } else {
                                    LOG.warn("{} -> skipped {} key due to invalid shape", jwks.location(), kty);
                                }
                            }
                            case "OKP" -> {
                                if (jwk.containsKey("crv") && jwk.containsKey("x") && !jwk.containsKey("d")) {
                                    try {
                                        JwsJwkVerifier v = JwsJwkVerifierFactory.buildEdEcVerifier(jwk);
                                        next.computeIfAbsent(v.getAlgorithm(), x -> new ArrayList<>()).add(v);
                                        LOG.info("{} -> registered {} key: alg={} kid={}", jwks.location(), kty, v.getAlgorithm(), v.getKeyId().orElse("None"));
                                    } catch (Exception ex) {
                                        LOG.warn("{} -> skipped {} key: {}", jwks.location(), kty, ex.getMessage());
                                    }
                                } else {
                                    LOG.warn("{} -> skipped {} key: invalid shape", jwks.location(), kty);
                                }
                            }
                            default -> LOG.warn("{} -> skipped key for unknown family: {}", jwks.location(), kty);
                        }
                    });
                    jwsJwkVerifiers.set(next);
                });
    }

    public boolean verify(Jws jws) {
        JwsAlgorithm jwsAlgorithm = jws.algorithm();
        if (jwsAlgorithm == JwsAlgorithm.NONE) {
            return true;
        }
        if (jwsAlgorithm == JwsAlgorithm.UNKNOWN) {
            return false;
        }
        Map<JwsAlgorithm, List<JwsJwkVerifier>> currentVerifiers = jwsJwkVerifiers.get();
        return currentVerifiers.get(jwsAlgorithm).stream()
                .filter(verifier -> jws.keyId() == null || verifier.getKeyId().isEmpty() || jws.keyId().equals(verifier.getKeyId().get()))
                .anyMatch(v -> v.verify(jws));
    }
}
