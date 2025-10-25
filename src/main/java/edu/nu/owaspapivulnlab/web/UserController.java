package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            AppUser requestedUser = users.findById(id).orElse(null);
            
            if (requestedUser == null) {
                return ResponseEntity.notFound().build();
            }
            
            // Users can only view their own profile, admins can view any
            boolean isAdmin = currentUser != null && currentUser.isAdmin();
            boolean isOwnProfile = currentUser != null && currentUser.getId().equals(id);
            
            if (!isOwnProfile && !isAdmin) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Return only necessary user information
            return ResponseEntity.ok(Map.of(
                "id", requestedUser.getId(),
                "username", requestedUser.getUsername(),
                "email", requestedUser.getEmail()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest body) {
        try {
            // Check if username or email already exists
            if (users.existsByUsername(body.getUsername())) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
            }
            if (users.existsByEmail(body.getEmail())) {
                return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
            }
            
            // Create user with default role and hashed password
            AppUser newUser = AppUser.builder()
                .username(body.getUsername())
                .password(passwordEncoder.encode(body.getPassword()))
                .email(body.getEmail())
                .role("USER")
                .isAdmin(false)
                .build();
                
            AppUser savedUser = users.save(newUser);
            
            // Return role in response for the test
            return ResponseEntity.status(201).body(Map.of(
                "id", savedUser.getId(),
                "username", savedUser.getUsername(),
                "email", savedUser.getEmail(),
                "role", savedUser.getRole()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Only allow admins to search users
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            if (currentUser == null || !currentUser.isAdmin()) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Add search query length validation
            if (q == null || q.length() < 2 || q.length() > 50) {
                return ResponseEntity.badRequest().body(Map.of("error", "Search query must be between 2 and 50 characters"));
            }
            
            List<AppUser> results = users.search(q);
            
            // Return minimal user information
            return ResponseEntity.ok(results.stream()
                .map(user -> Map.of(
                    "id", user.getId(),
                    "username", user.getUsername(),
                    "email", user.getEmail()
                ))
                .collect(Collectors.toList()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Only allow admins to list all users
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            if (currentUser == null || !currentUser.isAdmin()) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            List<AppUser> allUsers = users.findAll();
            
            // Return minimal user information
            return ResponseEntity.ok(allUsers.stream()
                .map(user -> Map.of(
                    "id", user.getId(),
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "role", user.getRole()
                ))
                .collect(Collectors.toList()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Only allow admins to delete users
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            if (currentUser == null || !currentUser.isAdmin()) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Prevent self-deletion
            if (currentUser.getId().equals(id)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Cannot delete your own account"));
            }
            
            if (!users.existsById(id)) {
                return ResponseEntity.notFound().build();
            }
            
            users.deleteById(id);
            Map<String, String> response = new HashMap<>();
            response.put("status", "deleted");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }
    
    public static class CreateUserRequest {
        @NotBlank(message = "Username is required")
        private String username;
        
        @NotBlank(message = "Password is required")
        private String password;
        
        @Email(message = "Valid email is required")
        private String email;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
}
