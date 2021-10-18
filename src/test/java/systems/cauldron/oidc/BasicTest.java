package systems.cauldron.oidc;

import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BasicTest {

    @Test
    public void basicTest() throws ExecutionException, InterruptedException {
        URI testProviderUri = URI.create("https://accounts.google.com/");
        JsonObject config = ConfigSource.getAsync(testProviderUri).get();
        JwtVerifier verifier = new JwtVerifier(config);
        CompletableFuture<Void> task = verifier.update();
        task.get();
        assertNotNull(verifier);
    }
}