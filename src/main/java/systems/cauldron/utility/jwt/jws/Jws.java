package systems.cauldron.utility.jwt.jws;

import systems.cauldron.utility.jwt.Jwt;

public record Jws(byte[] header, byte[] payload, byte[] signature, JwsAlgorithm algorithm,
                  String keyId) implements Jwt {
}
