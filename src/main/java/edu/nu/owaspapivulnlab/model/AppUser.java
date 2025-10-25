package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import lombok.*;

@Entity 
@Data 
@NoArgsConstructor 
@AllArgsConstructor 
@Builder
public class AppUser {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(unique = true)
    private String username;

    @NotBlank
    private String password;

    @Builder.Default
    private String role = "USER";
    
    @Builder.Default
    private boolean isAdmin = false;

    @Email
    private String email;
}
