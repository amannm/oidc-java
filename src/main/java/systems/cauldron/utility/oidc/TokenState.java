package systems.cauldron.utility.oidc;

import java.time.Instant;
import java.util.Set;

public record TokenState(String accessToken, Instant accessTokenExpiration, Set<String> accessTokenScopes,
                         String idToken, String refreshToken) {
}
