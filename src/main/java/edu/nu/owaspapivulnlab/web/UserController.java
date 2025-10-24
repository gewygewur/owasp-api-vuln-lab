package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // FIXED(API1: BOLA/IDOR) - ensure users can only access their own info unless admin
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized - please log in");
        }

        AppUser target = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));

        // Only the owner or admin can access the user info
        if (!me.isAdmin() && !me.getId().equals(target.getId())) {
            return ResponseEntity.status(403).body("Forbidden - you can only view your own profile");
        }

        // Avoid exposing password
        AppUser safeUser = new AppUser();
        safeUser.setId(target.getId());
        safeUser.setUsername(target.getUsername());
        safeUser.setEmail(target.getEmail());
        return ResponseEntity.ok(safeUser);
    }

    // FIXED(API6: Mass Assignment) - prevent clients from setting role/isAdmin directly
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body) {
        AppUser newUser = new AppUser();
        newUser.setUsername(body.getUsername());
        newUser.setPassword(body.getPassword()); 
        newUser.setEmail(body.getEmail());
        newUser.setRole("USER");
        newUser.setAdmin(false);
        users.save(newUser);

        Map<String, String> response = new HashMap<>();
        response.put("status", "user created safely");
        return ResponseEntity.ok(response);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style)
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // FIXED(API3: Excessive Data Exposure) - return limited info only (no passwords, roles, etc.)
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }

        List<Map<String, Object>> safeUsers = users.findAll().stream().map(u -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", u.getId());
            map.put("username", u.getUsername());
            map.put("email", u.getEmail());
            return map;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(safeUsers);
    }

    // FIXED(API5: Broken Function Level Authorization) - restrict delete to admins only
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized - please log in");
        }

        if (!me.isAdmin()) {
            return ResponseEntity.status(403).body("Forbidden - only admins can delete users");
        }

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "user deleted successfully");
        return ResponseEntity.ok(response);
    }
}
