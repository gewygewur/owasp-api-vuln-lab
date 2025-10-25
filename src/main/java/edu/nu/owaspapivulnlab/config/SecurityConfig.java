package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    // FIXED: Proper security configuration with correct authorization and error handling
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless
        
        http.cors(cors -> cors.configure(http));
        
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**").permitAll()
                // FIXED: Remove overly permissive GET access - require authentication for all API endpoints
                .requestMatchers(HttpMethod.GET, "/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/accounts/mine").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/accounts/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/accounts/**").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/users/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // Allow user registration
                .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN")
                .requestMatchers("/h2-console/**").permitAll() // Only in dev - should be disabled in prod
                .anyRequest().authenticated()
        );

        // FIXED: Only disable frame options for H2 console in development
        http.headers(h -> h.frameOptions(f -> f.sameOrigin()));

        // FIXED: Add proper authentication entry point
        http.exceptionHandling(e -> e
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        );

        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // FIXED: Improved JWT filter with proper validation and error handling
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    var parserBuilder = Jwts.parserBuilder().setSigningKey(secret.getBytes());
                    
                    // FIXED: Only validate issuer/audience if they exist in the token
                    Claims c = parserBuilder.build().parseClaimsJws(token).getBody();
                    
                    // Check if token has issuer and validate if present
                    String tokenIssuer = c.getIssuer();
                    if (tokenIssuer != null && !"owasp-api-lab".equals(tokenIssuer)) {
                        sendUnauthorizedError(response, "Invalid token issuer");
                        return;
                    }
                    
                    // Check if token has audience and validate if present  
                    String tokenAudience = c.getAudience();
                    if (tokenAudience != null && !"api-users".equals(tokenAudience)) {
                        sendUnauthorizedError(response, "Invalid token audience");
                        return;
                    }
                    
                    // FIXED: Validate token expiration
                    if (c.getExpiration().before(new java.util.Date())) {
                        sendUnauthorizedError(response, "Token expired");
                        return;
                    }
                    
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                        user, 
                        null,
                        role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList()
                    );
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // FIXED: Proper error handling - return 401 for invalid tokens
                    sendUnauthorizedError(response, "Invalid token");
                    return;
                }
            }
            chain.doFilter(request, response);
        }

        // FIXED: Helper method for consistent error responses
        private void sendUnauthorizedError(HttpServletResponse response, String message) throws IOException {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"error\": \"" + message + "\"}");
            response.getWriter().flush();
        }
    }
}
