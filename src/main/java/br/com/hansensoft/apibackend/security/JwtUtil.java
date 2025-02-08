package br.com.hansensoft.apibackend.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * Utility class for handling JSON Web Tokens (JWT). This component provides methods
 * for generating, validating, and extracting information (specifically, the email) from JWTs.
 * It uses a secret key to sign and verify the tokens.
 **/
@Component
public class JwtUtil {
    
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    /**
     * Generates a JWT token for the given email address.  The token includes the email as the
     * subject, the issue date, and the expiration date.
     *
     * @param email The email address to include as the subject of the JWT.
     * @return The generated JWT token.
     */
    public String generateToken(String email) {
        return JWT.create()
                .withSubject(email)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + expirationTime))
                .sign(Algorithm.HMAC256(secretKey));
    }

    /**
     * Validates the given JWT token.  It verifies the token's signature against the secret key
     * and checks if the token has expired.
     *
     * @param token The JWT token to validate.
     * @return {@code true} if the token is valid, {@code false} otherwise.
     */
    public boolean validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(secretKey)).build().verify(token);
            return true;
        } catch (JWTVerificationException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Extracts the email address from the given JWT token.  This method assumes that the email
     * address is stored in the "subject" claim of the token.
     *
     * @param token The JWT token to extract the email from.
     * @return The email address extracted from the token's subject claim.
     */
    public String extractEmail(String token) {
        return JWT.require(Algorithm.HMAC256(secretKey)).build().verify(token).getSubject();
    }
}