package systems.cauldron.utility;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import systems.cauldron.utility.oidc.IdTokenVerifier;
import systems.cauldron.utility.oidc.ProviderConfig;

import java.net.URI;
import java.util.concurrent.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicTest {

    private final static Logger LOG = LogManager.getLogger(BasicTest.class);

    @Test
    public void basicTest() throws ExecutionException, InterruptedException, TimeoutException {
        URI[] providerUris = Stream.of(
                        "https://accounts.google.com",
                        "https://appleid.apple.com",
                        "https://login.microsoftonline.com/common/v2.0",
                        "https://www.facebook.com",
                        "https://api.login.yahoo.com",
                        "https://www.paypalobjects.com",
                        "https://login.salesforce.com")
                .map(URI::create)
                .toArray(URI[]::new);
        ConcurrentHashMap<URI, IdTokenVerifier> jwsVerifiers = new ConcurrentHashMap<>();
        CompletableFuture.allOf(Stream.of(providerUris)
                        .map(providerUri -> buildVerifier(providerUri)
                                .thenAccept(idTokenVerifier -> jwsVerifiers.put(providerUri, idTokenVerifier)))
                        .toArray(CompletableFuture[]::new))
                .get(360L, TimeUnit.SECONDS);
        assertEquals(providerUris.length, jwsVerifiers.values().size());
    }

    private CompletableFuture<IdTokenVerifier> buildVerifier(URI providerUri) {
        return ProviderConfig.create(providerUri)
                        .thenCompose(config -> config.verifier().refresh()
                                .thenApply(x -> new IdTokenVerifier("", config)));
    }
}