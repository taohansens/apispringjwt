package br.com.hansensoft.apibackend.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuration class for Spring Security.  This class defines the security filter chain,
 * configures authorization rules, and provides a bean for password encoding.
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * The JWT authentication filter, responsible for authenticating users based on JWT tokens.
     * This filter is injected via constructor injection.
     */
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Configures the security filter chain.  This method defines the order of filters,
     * authorization rules, and session management policy.
     *
     * @param http The {@link HttpSecurity} object to configure.
     * @return The configured {@link SecurityFilterChain}.
     * @throws Exception If an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)  // Disable CSRF protection (not needed for stateless APIs)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Configure session management to be stateless (no sessions are created)
                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Allow unauthenticated access to the login and register endpoints
                        .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                        // All other requests must be authenticated
                        .anyRequest().authenticated()
                )
                // Add the JWT authentication filter before the UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build(); // Build the SecurityFilterChain

    }

    /**
     * Provides a bean for encoding passwords using BCrypt.  BCrypt is a strong password
     * hashing algorithm that is recommended for storing passwords securely.
     *
     * @return A {@link PasswordEncoder} instance using BCrypt.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
         return new BCryptPasswordEncoder();
    }

}