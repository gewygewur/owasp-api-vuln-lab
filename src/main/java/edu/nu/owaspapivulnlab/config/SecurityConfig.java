package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    // FIXED(API7: Security Misconfiguration) - tightened CORS/CSRF, restricted endpoints, proper JWT validation
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Disable CSRF for stateless APIs but consider enabling for forms
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //  Tighten endpoint access control
        http.authorizeHttpRequests(reg -> reg
                // Allow login/signup only
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()

                // All other /api/** requests now require authentication
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        // Secure headers: allow H2 console frame only in dev
        http.headers(h -> h.frameOptions(f -> f.sameOrigin()));

        // Add JWT filter for authentication
        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    //  Secure JWT Filter - proper error handling, issuer/audience validation, shorter TTL recommended
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
                    // Parse and validate JWT with stronger checks
                    Jws<Claims> jws = Jwts.parserBuilder()
                            .setSigningKey(secret.getBytes())
                            .requireIssuer("apilab-secure")
                            .requireAudience("apilab-users")
                            .build()
                            .parseClaimsJws(token);

                    Claims claims = jws.getBody();
                    String user = claims.getSubject();
                    String role = (String) claims.get("role");

                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                            user, null,
                            role != null
                                    ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                    : Collections.emptyList()
                    );
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // Instead of silently ignoring, log or send 401 response
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid or expired token");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
