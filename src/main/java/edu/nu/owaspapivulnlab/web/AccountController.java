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
import java.util.Optional;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            Optional<Account> accountOpt = accounts.findById(id);
            if (accountOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            Account account = accountOpt.get();
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            
            // Check if the current user owns this account
            if (currentUser == null || !account.getOwnerUserId().equals(currentUser.getId())) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            return ResponseEntity.ok(account.getBalance());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Validate amount
            if (amount == null || amount <= 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
            }
            
            Optional<Account> accountOpt = accounts.findById(id);
            if (accountOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            Account account = accountOpt.get();
            AppUser currentUser = users.findByUsername(auth.getName()).orElse(null);
            
            // Check if the current user owns this account
            if (currentUser == null || !account.getOwnerUserId().equals(currentUser.getId())) {
                return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            }
            
            // Check sufficient balance
            if (account.getBalance() < amount) {
                return ResponseEntity.badRequest().body(Map.of("error", "Insufficient balance"));
            }
            
            account.setBalance(account.getBalance() - amount);
            accounts.save(account);
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "ok");
            response.put("remaining", account.getBalance());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }

    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        try {
            if (auth == null || auth.getName() == null) {
                return ResponseEntity.ok(Collections.emptyList());
            }
            
            AppUser me = users.findByUsername(auth.getName()).orElse(null);
            if (me == null) {
                return ResponseEntity.ok(Collections.emptyList());
            }
            
            // Return only necessary account information
            return ResponseEntity.ok(accounts.findByOwnerUserId(me.getId()).stream()
                .map(acc -> Map.of(
                    "id", acc.getId(),
                    "iban", acc.getIban(),
                    "balance", acc.getBalance()
                ))
                .toList());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
        }
    }
}
