package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    // simple in-memory rate tracking map
    private final Map<String, Long> lastRequestTime = new HashMap<>();
    private final Map<String, Integer> requestCount = new HashMap<>();

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // FIXED(API1: BOLA)
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized - please log in");
        }
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body("Forbidden - you can only view your own account balance");
        }
        return ResponseEntity.ok(a.getBalance());
    }

    // FIXED(API4 + API5): Added simple rate limiting, input validation, and ownership check
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        String username = (auth != null) ? auth.getName() : "anonymous";

        // --- Simple rate limiter (max 5 requests per minute per user) ---
        long now = System.currentTimeMillis();
        long oneMinute = 60 * 1000; // 60 seconds
        long last = lastRequestTime.getOrDefault(username, 0L);
        int count = requestCount.getOrDefault(username, 0);

        if (now - last < oneMinute) {
            count++;
            if (count > 5) {
                return ResponseEntity.status(429).body("Too many requests - please wait and try again");
            }
        } else {
            count = 1; // reset count after 1 minute
            lastRequestTime.put(username, now);
        }
        requestCount.put(username, count);

        // --- Input validation ---
        if (amount == null || amount <= 0) {
            return ResponseEntity.badRequest().body("Invalid amount - must be greater than zero");
        }
        if (amount > 100000) {
            return ResponseEntity.badRequest().body("Amount too large - exceeds transfer limit");
        }

        // --- Fetch account ---
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        // --- API5: Ownership check (only owner or admin can transfer) ---
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized - please log in");
        }

        boolean isAdmin = me.isAdmin();
        if (!isAdmin && !a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body("Forbidden - only account owner or admin can transfer funds");
        }

        // --- Perform transfer ---
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // Safe-ish helper to view my accounts
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
