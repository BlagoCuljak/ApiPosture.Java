package com.apiposture.core.models;

/**
 * Severity levels for security findings.
 */
public enum Severity {
    INFO(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4);

    private final int level;

    Severity(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }

    /**
     * Check if this severity is at least as severe as the given severity.
     */
    public boolean isAtLeast(Severity other) {
        return this.level >= other.level;
    }

    /**
     * Parse severity from string, case-insensitive.
     */
    public static Severity fromString(String value) {
        if (value == null || value.isBlank()) {
            return INFO;
        }
        try {
            return Severity.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return INFO;
        }
    }
}
