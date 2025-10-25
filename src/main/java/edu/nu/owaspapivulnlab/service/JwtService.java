package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    // FIXED: Improved JWT generation with proper claims and shorter TTL
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        
        return Jwts.builder()
                .setSubject(subject)
                .setClaims(claims) // FIXED: Use setClaims instead of addClaims
                .setIssuer("owasp-api-lab") // FIXED: Add issuer
                .setAudience("api-users")   // FIXED: Add audience
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .signWith(SignatureAlgorithm.HS256, secret.getBytes()) // FIXED: Correct parameter order
                .compact();
    }
    
    // FIXED: Add token validation method
    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(secret.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody();
            
            // Check expiration
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
    
    // FIXED: Add method to extract username from token
    public String extractUsername(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(secret.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        } catch (Exception e) {
            return null;
        }
    }
}
