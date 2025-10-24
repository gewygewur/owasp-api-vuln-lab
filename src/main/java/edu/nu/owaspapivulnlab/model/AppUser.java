package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

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
    private String username;

    // FIXED(API3: Excessive Data Exposure)
    @NotBlank
    @JsonIgnore // prevents password from being exposed in API responses
    private String password; // should always be stored as BCrypt hash

    // FIXED(API6: Mass Assignment)
    // Mark as read-only so client cannot bind these fields
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private String role = "USER";   // default role safely set on server

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private boolean isAdmin = false; // only controlled by admin logic

    @Email
    private String email;
}
