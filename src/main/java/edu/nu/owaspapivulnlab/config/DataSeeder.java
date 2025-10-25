package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder passwordEncoder) {
        return args -> {
            if (users.count() == 0) {
                // FIXED: Create users with specific IDs for testing
                AppUser u1 = AppUser.builder()
                    .id(1L) // FIXED: Set specific ID for Alice
                    .username("alice")
                    .password(passwordEncoder.encode("alice123"))
                    .email("alice@cydea.tech")
                    .role("USER")
                    .isAdmin(false)
                    .build();
                
                AppUser u2 = AppUser.builder()
                    .id(2L) // FIXED: Set specific ID for Bob
                    .username("bob")
                    .password(passwordEncoder.encode("bob123"))
                    .email("bob@cydea.tech")
                    .role("ADMIN")
                    .isAdmin(true)
                    .build();
                
                // FIXED: Save users first to ensure IDs are set
                AppUser savedAlice = users.save(u1);
                AppUser savedBob = users.save(u2);
                
                // FIXED: Create accounts with known owner IDs
                accounts.save(Account.builder()
                    .ownerUserId(savedAlice.getId())
                    .iban("PK00-ALICE")
                    .balance(1000.0)
                    .build());
                    
                accounts.save(Account.builder()
                    .ownerUserId(savedBob.getId())
                    .iban("PK00-BOB")
                    .balance(5000.0)
                    .build());
                    
                System.out.println("DEBUG: Seeded Alice with ID: " + savedAlice.getId());
                System.out.println("DEBUG: Seeded Bob with ID: " + savedBob.getId());
            }
        };
    }
}
