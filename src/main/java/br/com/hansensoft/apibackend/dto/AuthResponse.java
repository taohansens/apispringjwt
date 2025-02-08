package br.com.hansensoft.apibackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Represents the authentication response returned after a successful login or registration.
 * Contains the JWT token for subsequent authenticated requests and a message providing
 * additional information about the authentication process.
 */
@Data
@AllArgsConstructor
public class AuthResponse {
    /**
     * The JSON Web Token (JWT) that the client should use for authenticating
     * subsequent requests to protected resources.  This token is typically
     * included in the `Authorization` header of HTTP requests.
     */
    private String token;
    /**
     * A message providing additional information about the authentication process.
     * This could include success messages, warnings, or error messages.  For example:
     * "Login successful", "User registered successfully", or "Invalid credentials".
     */
    private String message;
}