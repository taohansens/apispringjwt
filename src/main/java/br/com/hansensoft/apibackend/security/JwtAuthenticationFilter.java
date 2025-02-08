package br.com.hansensoft.apibackend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.hansensoft.apibackend.model.User;
import br.com.hansensoft.apibackend.repository.jpa.UserRepository;

import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;

import java.util.Collections;

/**
 * A Spring component that acts as a JWT authentication filter.  This filter intercepts incoming
 * HTTP requests, extracts the JWT from the `Authorization` header, validates it, and
 * authenticates the user if the token is valid.  This filter is executed once per request.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    /**
     * Performs the filtering logic for JWT authentication.  This method is called once for each
     * incoming request.
     *
     * @param request     The HTTP request.
     * @param response    The HTTP response.
     * @param chain       The filter chain.
     * @throws ServletException If a servlet exception occurs.
     * @throws IOException      If an I/O exception occurs.
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain) throws ServletException, IOException {

        // Get token from the Authorization header
        String authHeaders = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeaders == null || !authHeaders.startsWith("Bearer ")) {
            // No token found or invalid format, continue with the filter chain
            chain.doFilter(request, response);
            return;
        }

        // Extract the token from the "Bearer <token>" format
        String token = authHeaders.substring(7);
        // Extract the email address from the JWT
        String email = jwtUtil.extractEmail(token);

        // If the email is found and no authentication is currently present in the security context
        if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Retrieve the user from the database using the email
            User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
            // Create a UserDetails object from the retrieved user
            UserDetails userDetails = org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
                    .password(user.getPassword())
                    .authorities(Collections.emptyList()) // Replace with actual roles/authorities if needed
                    .build();

            // Validate the JWT
            if (jwtUtil.validateToken(token)) {
                // Create an authentication token
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // Set the authentication details from the request
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        // Continue with the filter chain
        chain.doFilter(request, response);
    }
}
