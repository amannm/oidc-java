package systems.cauldron.oidc;

import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BasicTest {

    @Test
    public void basicTest() throws ExecutionException, InterruptedException {
        List<URI> providerUris = Stream.of(
                "https://accounts.google.com/",
                "https://appleid.apple.com/",
                "https://login.microsoftonline.com/common/v2.0/",
                "https://www.facebook.com/",
                "https://api.login.yahoo.com/",
                "https://www.paypalobjects.com/"
        ).map(URI::create).collect(Collectors.toList());
        for (URI providerUri : providerUris) {
            JsonObject config = ConfigSource.getAsync(providerUri).get();
            JwtVerifier verifier = new JwtVerifier(config);
            CompletableFuture<Void> task = verifier.update();
            task.get();
            assertNotNull(verifier);
        }
    }
}