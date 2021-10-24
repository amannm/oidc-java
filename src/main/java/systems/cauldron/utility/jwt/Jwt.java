package systems.cauldron.utility.jwt;

import systems.cauldron.utility.JsonUtility;
import systems.cauldron.utility.jwt.jws.Jws;
import systems.cauldron.utility.jwt.jws.JwsAlgorithm;

import javax.json.JsonObject;
import java.nio.charset.StandardCharsets;

public interface Jwt {

    byte[] header();

    byte[] payload();

    byte[] signature();

    String keyId();

    static Jwt parse(String token) {
        String[] parts = splitToken(token);
        byte[] header = parts[0].getBytes(StandardCharsets.UTF_8);
        byte[] payload = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] signature = parts[2].getBytes(StandardCharsets.UTF_8);
        JsonObject joseHeader = JsonUtility.readJson(header);
        if (joseHeader.containsKey("enc")) {
            throw new UnsupportedOperationException("JWEs are not supported");
        } else {
            String alg = joseHeader.getString("alg");
            JwsAlgorithm algorithm = JwsAlgorithm.fromString(alg);
            if (algorithm == JwsAlgorithm.UNKNOWN) {
                throw new UnsupportedOperationException("unsupported JWS algorithm: " + alg);
            }
            String keyId = joseHeader.containsKey("kid") ? joseHeader.getString("kid") : null;
            return new Jws(header, payload, signature, algorithm, keyId);
        }
    }

    private static String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new RuntimeException("invalid number of token parts: " + parts.length);
        }
        return parts;
    }
}
