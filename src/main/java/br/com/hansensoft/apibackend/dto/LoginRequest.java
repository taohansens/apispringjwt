package br.com.hansensoft.apibackend.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Represents the login request received from a client, containing the user's email and password.
 * This class includes validation annotations to ensure that the email and password are provided
 * and that the email is in a valid format.
 */
@Data
public class LoginRequest {
    /**
     * The user's email address.  Must not be blank and must be a valid email format.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    /**
     * The user's password.  Must not be blank.
     */
    @NotBlank(message = "Password is required")
    private String password;
}