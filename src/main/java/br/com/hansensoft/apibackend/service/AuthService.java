package br.com.hansensoft.apibackend.service;

import lombok.RequiredArgsConstructor;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.hansensoft.apibackend.dto.AuthRequest;
import br.com.hansensoft.apibackend.dto.AuthResponse;
import br.com.hansensoft.apibackend.dto.LoginRequest;
import br.com.hansensoft.apibackend.dto.UserDTO;
import br.com.hansensoft.apibackend.exception.service.AccountException;
import br.com.hansensoft.apibackend.exception.service.AuthException;
import br.com.hansensoft.apibackend.model.Role;
import br.com.hansensoft.apibackend.model.User;
import br.com.hansensoft.apibackend.repository.jpa.RoleRepository;
import br.com.hansensoft.apibackend.repository.jpa.UserRepository;
import br.com.hansensoft.apibackend.security.JwtUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Service class for handling authentication-related operations, such as user registration and login.
 * This service interacts with the {@link UserRepository} for user data access and the
 * {@link JwtUtil} for JWT token generation.
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    /**
     * Repository for accessing user data.  Used for checking email existence, saving new users,
     * and retrieving user details during login.  Injected via constructor injection.
     */
    private final UserRepository userRepository;
    /**
     * Repository for accessing role data.  Used for checking roles types available.  Injected 
     * via constructor injection.
     */
    private final RoleRepository roleRepository;
    /**
     * Utility class for JWT operations (generating tokens).  Used for creating JWT tokens
     * upon successful registration or login.  Injected via constructor injection.
     */
    private final JwtUtil jwtUtil;
    /**
     * Password encoder for hashing and verifying passwords.  Used to securely store user passwords
     * during registration and to verify passwords during login.  A BCryptPasswordEncoder is
     * instantiated here.  Consider making this injectable.
     */
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Registers a new user in the system.
     *
     * @param request The {@link AuthRequest} containing the user's registration details.
     * @return An {@link AuthResponse} containing the JWT token and a success message.
     * @throws RuntimeException If the email is already in use.
     */
    public AuthResponse register(AuthRequest request) {
        // Check if email already in use
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AccountException("Email is already in use.");
        }

        // Hash Password
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // Assign default role if no one is provided.
        Set<Role> roles = new HashSet<>();
        if (request.getRoles() == null || request.getRoles().isEmpty()) {
            Role userRole = roleRepository.findByName("USER")
                    .orElseThrow(() -> new RuntimeException("Role not found"));
            roles.add(userRole);
        } else {
            for (String roleName : request.getRoles()) {
                Role role = roleRepository.findByName(roleName)
                        .orElseThrow(() -> new RuntimeException("Role not found"));
                roles.add(role);
            }
        }

        // Create User
        User user = new User(null, request.getUsername(), request.getEmail(), hashedPassword, roles);
        userRepository.save(user);

        // Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail());

        return new AuthResponse(token, "User registered successfully!");
    }

    /**
     * Logs in an existing user.
     *
     * @param request The {@link LoginRequest} containing the user's email and password.
     * @return An {@link AuthResponse} containing the JWT token and a success message.
     * @throws RuntimeException If the email or password is invalid.
     */
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new AuthException("Invalid email or password"));

        // Verify Password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AuthException("Invalid email or Password");
        }

        // Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail());

        return new AuthResponse(token, "Login Successful");
    }

    public UserDTO getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found!"));
        return convertToUserDTO(user);
    }

    public UserDTO convertToUserDTO(User user) {
    List<String> roles = user.getRoles().stream()
            .map(Role::getName)
            .toList();
    return new UserDTO(user.getUsername(), user.getEmail(), roles);
    }
}