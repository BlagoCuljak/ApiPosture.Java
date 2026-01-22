package com.apiposture.cli.output;

import com.apiposture.core.models.ScanResult;

/**
 * Interface for formatting scan results.
 */
public interface OutputFormatter {

    /**
     * Format scan results to a string representation.
     *
     * @param result The scan result to format
     * @return Formatted string output
     */
    String format(ScanResult result);
}
