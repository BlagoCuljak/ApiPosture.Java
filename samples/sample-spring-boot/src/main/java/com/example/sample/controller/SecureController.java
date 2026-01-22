package com.example.sample.controller;

import jakarta.annotation.security.PermitAll;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Secure controller demonstrating proper security practices.
 * This controller shows how endpoints should be properly secured.
 */
@RestController
@RequestMapping("/api/secure")
@PreAuthorize("isAuthenticated()")
public class SecureController {

    /**
     * Properly secured with authentication - inherits from class
     */
    @GetMapping("/profile")
    public Map<String, String> getProfile() {
        return Map.of("username", "john.doe", "email", "john@example.com");
    }

    /**
     * Properly secured with specific role
     */
    @GetMapping("/sensitive")
    @PreAuthorize("hasRole('DATA_ANALYST')")
    public List<String> getSensitiveData() {
        return List.of("Sensitive data 1", "Sensitive data 2");
    }

    /**
     * Explicitly public with @PermitAll - this is intentional
     */
    @GetMapping("/public-info")
    @PermitAll
    public Map<String, String> getPublicInfo() {
        return Map.of("version", "1.0.0", "status", "healthy");
    }

    /**
     * Properly secured write operation
     */
    @PostMapping("/data")
    @PreAuthorize("hasRole('DATA_MANAGER')")
    public String createData(@RequestBody String data) {
        return "Created: " + data;
    }

    /**
     * Properly secured write operation with multiple authorities
     */
    @PutMapping("/settings")
    @PreAuthorize("hasAnyAuthority('SETTINGS_WRITE', 'ADMIN')")
    public String updateSettings(@RequestBody String settings) {
        return "Updated settings";
    }
}
