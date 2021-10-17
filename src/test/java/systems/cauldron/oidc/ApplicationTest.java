package systems.cauldron.oidc;

import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ApplicationTest {


    @Test
    public void basicTest() throws ExecutionException, InterruptedException {
        JsonObject result = DiscoveryClient.getAsync("https://accounts.google.com/").get();
        assertNotNull(result);
    }
}