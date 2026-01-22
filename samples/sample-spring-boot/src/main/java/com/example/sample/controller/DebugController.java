package com.example.sample.controller;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Debug controller demonstrating sensitive route issues.
 * This controller intentionally exposes debug endpoints publicly.
 */
@RestController
@RequestMapping("/api/debug")
public class DebugController {

    /**
     * AP007: Sensitive keyword 'debug' in public route
     * AP001: Public without explicit intent
     * AP008: No security annotation
     */
    @GetMapping("/config")
    public Map<String, String> getConfig() {
        return Map.of(
                "database.url", "jdbc:postgresql://localhost:5432/db",
                "api.key", "secret-key-123"
        );
    }

    /**
     * AP007: Sensitive keyword 'debug' in public route
     * AP007: Also 'export' in the route
     */
    @GetMapping("/export/logs")
    public String exportLogs() {
        return "Application logs...";
    }

    /**
     * AP007: Sensitive keyword 'internal' in public route
     */
    @GetMapping("/internal/metrics")
    public Map<String, Integer> getMetrics() {
        return Map.of("requests", 1000, "errors", 5);
    }
}
