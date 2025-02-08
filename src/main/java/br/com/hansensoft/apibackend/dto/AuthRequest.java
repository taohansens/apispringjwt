package br.com.hansensoft.apibackend.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

/**
 * Represents the authentication request received from a client for user registration or login.
 * This class encapsulates the user's credentials (username, email, password) and desired roles,
 * and includes validation annotations to ensure data integrity.
 */
@Data
public class AuthRequest {
    /**
     * The user's username.  Must not be blank.
     */
    @NotBlank(message = "Username is required")
    private String username;

    /**
     * The user's email address.  Must not be blank and must be a valid email format.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    /**
     * The user's password.  Must not be blank and must be at least 6 characters long.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    /**
     * The set of roles the user is requesting. This field is optional and may be used
     * during user registration to assign initial roles to the user. If not provided,
     * a default role may be assigned by the server.
     */
    private Set<String> roles;
}