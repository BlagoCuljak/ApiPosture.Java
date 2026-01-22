package com.example.sample.controller;

import jakarta.annotation.security.PermitAll;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin controller demonstrating authorization conflicts.
 */
@RestController
@RequestMapping("/api/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    /**
     * Properly secured - inherits class @PreAuthorize
     */
    @GetMapping
    public List<String> getAllUsers() {
        return List.of("user1", "user2", "admin");
    }

    /**
     * AP003: @PermitAll overrides class-level @PreAuthorize
     * AP007: 'admin' in public route
     */
    @GetMapping("/public-admin-info")
    @PermitAll
    public Map<String, String> getPublicAdminInfo() {
        return Map.of("adminCount", "5", "lastLogin", "2024-01-01");
    }

    /**
     * Properly secured admin endpoint
     */
    @PostMapping
    public String createUser(@RequestBody String username) {
        return "Created user: " + username;
    }

    /**
     * Properly secured admin endpoint
     */
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable String id) {
        // Delete user
    }
}
