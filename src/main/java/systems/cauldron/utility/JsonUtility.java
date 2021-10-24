package systems.cauldron.utility;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class JsonUtility {
    public static JsonObject readJson(byte[] json) {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(json))) {
            return reader.readObject();
        }
    }

    public static JsonObject readJson(String json) {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)))) {
            return reader.readObject();
        }
    }

    public static Stream<String> streamArray(JsonObject object, String key) {
        return object.getJsonArray(key).stream()
                .map(jv -> (JsonString) jv)
                .map(JsonString::getString);
    }
}
