package edu.nu.owaspapivulnlab.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import edu.nu.owaspapivulnlab.model.AppUser;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);

    @Query("SELECT u FROM AppUser u WHERE u.username LIKE CONCAT('%', :query, '%') OR u.email LIKE CONCAT('%', :query, '%')")
    List<AppUser> search(String query);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
    
    // FIXED: Add missing existsById method
    boolean existsById(Long id);
}
