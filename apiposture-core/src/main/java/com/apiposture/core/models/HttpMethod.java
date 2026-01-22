package com.apiposture.core.models;

import java.util.EnumSet;
import java.util.Set;

/**
 * HTTP methods supported for endpoint detection.
 */
public enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS;

    /**
     * All HTTP methods that modify data (write operations).
     */
    public static final Set<HttpMethod> WRITE_METHODS = EnumSet.of(POST, PUT, DELETE, PATCH);

    /**
     * All HTTP methods that only read data.
     */
    public static final Set<HttpMethod> READ_METHODS = EnumSet.of(GET, HEAD, OPTIONS);

    /**
     * Check if this method is a write operation.
     */
    public boolean isWriteMethod() {
        return WRITE_METHODS.contains(this);
    }

    /**
     * Check if this method is a read operation.
     */
    public boolean isReadMethod() {
        return READ_METHODS.contains(this);
    }

    /**
     * Parse HTTP method from Spring annotation name.
     * e.g., "GetMapping" -> GET, "PostMapping" -> POST
     */
    public static HttpMethod fromAnnotationName(String annotationName) {
        if (annotationName == null) {
            return null;
        }
        String name = annotationName.replace("Mapping", "").toUpperCase();
        try {
            return HttpMethod.valueOf(name);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
