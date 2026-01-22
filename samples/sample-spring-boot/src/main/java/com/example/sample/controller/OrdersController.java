package com.example.sample.controller;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Orders controller demonstrating role-based security patterns.
 */
@RestController
@RequestMapping("/api/orders")
public class OrdersController {

    /**
     * AP005: Excessive roles (>3)
     * AP006: Weak role naming (User, Admin, Manager)
     */
    @GetMapping
    @RolesAllowed({"User", "Admin", "Manager", "Support", "Sales"})
    public List<String> getAllOrders() {
        return List.of("Order 1", "Order 2");
    }

    /**
     * Well-defined role access
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ORDERS_VIEWER')")
    public String getOrder(@PathVariable String id) {
        return "Order: " + id;
    }

    /**
     * Well-defined role access
     */
    @PostMapping
    @PreAuthorize("hasRole('ORDERS_MANAGER')")
    public String createOrder(@RequestBody String order) {
        return "Created: " + order;
    }

    /**
     * AP002: @PermitAll on write operation
     */
    @PutMapping("/guest/{id}")
    @PermitAll
    public String updateGuestOrder(@PathVariable String id, @RequestBody String order) {
        return "Updated guest order: " + id;
    }

    /**
     * AP006: Weak role naming
     */
    @DeleteMapping("/{id}")
    @Secured("ROLE_ADMIN")
    public void deleteOrder(@PathVariable String id) {
        // Delete order
    }
}
