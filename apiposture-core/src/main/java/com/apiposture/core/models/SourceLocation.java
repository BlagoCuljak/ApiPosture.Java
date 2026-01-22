package com.apiposture.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents the source code location of an endpoint or finding.
 */
public record SourceLocation(
        @JsonProperty("filePath") String filePath,
        @JsonProperty("lineNumber") int lineNumber,
        @JsonProperty("column") int column
) {
    /**
     * Create a location with only file path and line number.
     */
    public SourceLocation(String filePath, int lineNumber) {
        this(filePath, lineNumber, 0);
    }

    /**
     * Format as "file:line" or "file:line:column".
     */
    @Override
    public String toString() {
        if (column > 0) {
            return "%s:%d:%d".formatted(filePath, lineNumber, column);
        }
        return "%s:%d".formatted(filePath, lineNumber);
    }

    /**
     * Get relative path from a base directory.
     */
    public String relativePath(String baseDir) {
        if (baseDir == null || filePath == null) {
            return filePath;
        }
        if (filePath.startsWith(baseDir)) {
            String relative = filePath.substring(baseDir.length());
            if (relative.startsWith("/") || relative.startsWith("\\")) {
                relative = relative.substring(1);
            }
            return relative;
        }
        return filePath;
    }
}
