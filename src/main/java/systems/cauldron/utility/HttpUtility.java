package systems.cauldron.utility;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

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

    public static CompletableFuture<JsonObject> postForJsonAsync(URI uri, Map<String, String> parameters) {
        String body = urlEncode(parameters);
        return HttpClient.newBuilder()
                .connectTimeout(Duration.of(5L, ChronoUnit.SECONDS))
                .build()
                .sendAsync(HttpRequest.newBuilder()
                        .uri(uri)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .setHeader("Content-Type", "application/x-www-form-urlencoded")
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

    public static String urlEncode(Map<String, String> parameters) {
        return parameters.entrySet().stream()
                .map(e -> String.join("=", urlEncode(e.getKey()), urlEncode(e.getValue())))
                .collect(Collectors.joining("&"));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

}
