package com.apiposture.core.discovery;

import com.apiposture.core.models.Endpoint;
import com.github.javaparser.ast.CompilationUnit;

import java.util.List;

/**
 * Interface for discovering API endpoints from source code.
 */
public interface EndpointDiscoverer {

    /**
     * Discover endpoints from a compilation unit.
     *
     * @param compilationUnit The parsed Java source file
     * @param filePath The absolute path to the source file
     * @return List of discovered endpoints
     */
    List<Endpoint> discover(CompilationUnit compilationUnit, String filePath);
}
