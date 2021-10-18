package systems.cauldron.oidc;

import javax.json.JsonObject;
import java.net.URI;
import java.util.concurrent.CompletableFuture;

public class ConfigSource {
    public static CompletableFuture<JsonObject> getAsync(URI providerUri) {
        URI configUri = providerUri.resolve(".well-known/openid-configuration");
        return HttpUtility.getJsonAsync(configUri);
    }
}