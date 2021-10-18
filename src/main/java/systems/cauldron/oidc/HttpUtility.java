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

public class HttpUtility {

    public static CompletableFuture<JsonObject> getJsonAsync(URI uri) {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.of(5L, ChronoUnit.SECONDS))
                .build()
                .sendAsync(HttpRequest.newBuilder()
                        .uri(uri)
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
