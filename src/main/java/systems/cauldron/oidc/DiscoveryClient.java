package systems.cauldron.oidc;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CompletableFuture;

public class DiscoveryClient {

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    public static CompletableFuture<JsonObject> getAsync(String providerUrl) {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.of(5L, ChronoUnit.SECONDS))
                .build()
                .sendAsync(HttpRequest.newBuilder()
                        .uri(URI.create(providerUrl + DISCOVERY_PATH))
                        .build(), HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> {
                    int statusCode = response.statusCode();
                    if (statusCode != 200) {
                        throw new RuntimeException("unexpected status code: " + statusCode);
                    }
                    try (JsonReader reader = Json.createReader(response.body())) {
                        return reader.readObject();
                    }
                });
    }
}