package com.apiposture.core.models;

/**
 * Type of endpoint based on how it's defined in the source code.
 */
public enum EndpointType {
    /**
     * Traditional Spring MVC controller endpoint.
     */
    CONTROLLER,

    /**
     * Spring WebFlux functional endpoint.
     */
    FUNCTIONAL
}
