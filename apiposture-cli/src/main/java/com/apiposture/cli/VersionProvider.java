package com.apiposture.cli;

import picocli.CommandLine.IVersionProvider;

/**
 * Reads the CLI version from the JAR manifest (Implementation-Version),
 * which is set by the Maven Shade plugin from ${project.version} at build time.
 */
public class VersionProvider implements IVersionProvider {

    @Override
    public String[] getVersion() {
        String version = getClass().getPackage().getImplementationVersion();
        return new String[]{"apiposture " + (version != null ? version : "unknown")};
    }
}
