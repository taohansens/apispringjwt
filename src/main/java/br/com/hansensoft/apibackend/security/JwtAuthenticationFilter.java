package br.com.hansensoft.apibackend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import br.com.hansensoft.apibackend.exception.StandardError;
import br.com.hansensoft.apibackend.model.User;
import br.com.hansensoft.apibackend.repository.jpa.UserRepository;

import java.io.IOException;
import java.time.Instant;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;

import java.util.stream.Collectors;

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

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain) throws ServletException, IOException {
        try {
        String authHeaders = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeaders == null || !authHeaders.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // Extract the token from the "Bearer <token>" format
        String token = authHeaders.substring(7);
        String email = jwtUtil.extractEmail(token);

        // If the email is found and no authentication is currently present in the security context
        if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found!"));
            UserDetails userDetails = org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
            .password(user.getPassword())
            .authorities(user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList()))
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
        } catch (JWTVerificationException e) {
            setErrorResponse(HttpStatus.UNAUTHORIZED, response, e.getMessage(), request.getRequestURI());
        }
    }
         

    private void setErrorResponse(HttpStatus status, HttpServletResponse response, String message, String path) throws IOException {
        StandardError error = new StandardError();
        error.setTimestamp(Instant.now());
        error.setStatus(status.value());
        error.setError(status.getReasonPhrase());
        error.setMessage(message);
        error.setPath(path);

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(convertObjectToJson(error));
    }

    private String convertObjectToJson(Object object) throws IOException {
        if (object == null) {
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper.writeValueAsString(object);
    }
}
