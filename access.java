@Component
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component

import java.net.URL;
import java.security.interfaces.RSAPublicKey;

public class AccessDecisionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isValidToken(request)) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Access Denied");
        }
    }

    private boolean isValidToken(HttpServletRequest request) {
            URL jwkSetURL = new URL(publicKeyUrl);
            JWKSet jwkSet = JWKSet.load(jwkSetURL);
            RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0); // Assuming there's only one key

            JWT jwt = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) rsaKey.toPublicKey());

            if (jwt.verify(verifier)) {
                JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
     
                return true;
            }
    }
}
