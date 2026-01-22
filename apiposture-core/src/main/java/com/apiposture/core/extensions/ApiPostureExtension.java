package com.apiposture.core.extensions;

import com.apiposture.core.models.ScanResult;

/**
 * Extension interface for ApiPosture Pro features.
 * Extensions can hook into the scan lifecycle to add custom functionality.
 */
public interface ApiPostureExtension {

    /**
     * Get the unique identifier for this extension.
     */
    String getId();

    /**
     * Get the display name for this extension.
     */
    String getName();

    /**
     * Get the version of this extension.
     */
    String getVersion();

    /**
     * Called before a scan starts.
     *
     * @param projectPath Path to the project being scanned
     */
    default void onScanStart(String projectPath) {
    }

    /**
     * Called after a scan completes.
     *
     * @param result The scan result
     */
    default void onScanComplete(ScanResult result) {
    }

    /**
     * Check if this extension is properly licensed.
     */
    default boolean isLicensed() {
        return false;
    }
}
