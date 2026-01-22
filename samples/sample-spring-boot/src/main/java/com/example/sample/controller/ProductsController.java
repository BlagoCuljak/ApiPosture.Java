package com.example.sample.controller;

import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Products controller demonstrating various security issues.
 * This controller intentionally has security problems for ApiPosture to detect.
 */
@RestController
@RequestMapping("/api/products")
public class ProductsController {

    /**
     * AP001: Public endpoint without explicit @PermitAll
     * AP008: Controller without security annotation
     */
    @GetMapping
    public List<String> getAllProducts() {
        return List.of("Product 1", "Product 2", "Product 3");
    }

    /**
     * AP004: Public write without any authorization (CRITICAL)
     * AP001: Public without explicit intent
     */
    @PostMapping
    public String createProduct(@RequestBody String product) {
        return "Created: " + product;
    }

    /**
     * AP004: Public write without any authorization (CRITICAL)
     */
    @PutMapping("/{id}")
    public String updateProduct(@PathVariable String id, @RequestBody String product) {
        return "Updated " + id + ": " + product;
    }

    /**
     * AP004: Public write without any authorization (CRITICAL)
     */
    @DeleteMapping("/{id}")
    public void deleteProduct(@PathVariable String id) {
        // Delete product
    }
}
