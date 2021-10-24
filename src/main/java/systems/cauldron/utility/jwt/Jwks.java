package systems.cauldron.utility.jwt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import systems.cauldron.utility.HttpUtility;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.net.URI;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public record Jwks(URI location) {

    private final static Logger LOG = LogManager.getLogger(Jwks.class);

    public CompletableFuture<List<JsonObject>> load() {
        return HttpUtility.getJsonAsync(location)
                .thenApply(jwksResponse -> jwksResponse.getJsonArray("keys"))
                .thenApply(array -> {
                    List<JsonObject> jwksResponse = array.stream().map(JsonValue::asJsonObject).collect(Collectors.toList());
                    LOG.info("{} -> found {} keys", location, jwksResponse.size());
                    return jwksResponse;
                });
    }
}
