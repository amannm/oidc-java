package systems.cauldron.utility;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import systems.cauldron.utility.oidc.ConfigSource;
import systems.cauldron.utility.oidc.IdTokenVerifier;

import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicTest {

    private final static Logger LOG = LogManager.getLogger(BasicTest.class);


    @Test
    public void basicTest() throws ExecutionException, InterruptedException, TimeoutException {
        String[] providers = new String[]{
                "https://accounts.google.com/",
                "https://appleid.apple.com/",
                "https://login.microsoftonline.com/common/v2.0/",
                "https://www.facebook.com/",
                "https://api.login.yahoo.com/",
                "https://www.paypalobjects.com/",
                "https://login.salesforce.com/"
        };
        ConcurrentHashMap<URI, IdTokenVerifier> idTokenVerifiers = new ConcurrentHashMap<>();
        CompletableFuture.allOf(Stream.of(providers)
                        .map(URI::create)
                        .map(providerUri -> ConfigSource.getAsync(providerUri)
                                .thenApply(IdTokenVerifier::new)
                                .thenCompose(verifier -> {
                                    idTokenVerifiers.put(providerUri, verifier);
                                    return verifier.refresh();
                                })
                        )
                        .toArray(CompletableFuture[]::new))
                .get(5L, TimeUnit.SECONDS);
        assertEquals(providers.length, idTokenVerifiers.values().size());
    }
}