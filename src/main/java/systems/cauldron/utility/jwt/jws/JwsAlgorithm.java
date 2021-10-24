package systems.cauldron.utility.jwt.jws;

public enum JwsAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES256K,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EDDSA,
    NONE,
    UNKNOWN;

    public static JwsAlgorithm fromString(String value) {
        return switch (value) {
            case "HS256" -> HS256;
            case "HS384" -> HS384;
            case "HS512" -> HS512;
            case "RS256" -> RS256;
            case "RS384" -> RS384;
            case "RS512" -> RS512;
            case "ES256" -> ES256;
            case "ES256K" -> ES256K;
            case "ES384" -> ES384;
            case "ES512" -> ES512;
            case "PS256" -> PS256;
            case "PS384" -> PS384;
            case "PS512" -> PS512;
            case "EdDSA" -> EDDSA;
            case "none" -> NONE;
            default -> UNKNOWN;
        };
    }
}
