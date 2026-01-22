package com.apiposture.core.extensions;

import java.util.*;

/**
 * Manages ApiPosture extensions for Pro features.
 */
public class ExtensionManager {

    private final Map<String, ApiPostureExtension> extensions = new LinkedHashMap<>();
    private final Map<String, ExtensionRule> extensionRules = new LinkedHashMap<>();

    /**
     * Register an extension.
     */
    public void registerExtension(ApiPostureExtension extension) {
        extensions.put(extension.getId(), extension);
    }

    /**
     * Unregister an extension.
     */
    public void unregisterExtension(String extensionId) {
        extensions.remove(extensionId);
        // Also remove rules from this extension
        extensionRules.entrySet().removeIf(e -> e.getValue().getExtensionId().equals(extensionId));
    }

    /**
     * Register an extension rule.
     */
    public void registerRule(ExtensionRule rule) {
        extensionRules.put(rule.getId(), rule);
    }

    /**
     * Get all registered extensions.
     */
    public List<ApiPostureExtension> getExtensions() {
        return new ArrayList<>(extensions.values());
    }

    /**
     * Get all registered extension rules.
     */
    public List<ExtensionRule> getExtensionRules() {
        return new ArrayList<>(extensionRules.values());
    }

    /**
     * Get licensed extension rules only.
     */
    public List<ExtensionRule> getLicensedRules() {
        return extensionRules.values().stream()
                .filter(rule -> {
                    var extension = extensions.get(rule.getExtensionId());
                    return extension != null && extension.isLicensed();
                })
                .toList();
    }

    /**
     * Get an extension by ID.
     */
    public Optional<ApiPostureExtension> getExtension(String extensionId) {
        return Optional.ofNullable(extensions.get(extensionId));
    }

    /**
     * Get an extension rule by ID.
     */
    public Optional<ExtensionRule> getRule(String ruleId) {
        return Optional.ofNullable(extensionRules.get(ruleId));
    }

    /**
     * Check if any extensions are loaded.
     */
    public boolean hasExtensions() {
        return !extensions.isEmpty();
    }

    /**
     * Notify extensions that a scan is starting.
     */
    public void notifyScanStart(String projectPath) {
        extensions.values().forEach(ext -> {
            try {
                ext.onScanStart(projectPath);
            } catch (Exception e) {
                // Log and continue
                System.err.println("Extension " + ext.getId() + " failed on scan start: " + e.getMessage());
            }
        });
    }

    /**
     * Notify extensions that a scan is complete.
     */
    public void notifyScanComplete(com.apiposture.core.models.ScanResult result) {
        extensions.values().forEach(ext -> {
            try {
                ext.onScanComplete(result);
            } catch (Exception e) {
                // Log and continue
                System.err.println("Extension " + ext.getId() + " failed on scan complete: " + e.getMessage());
            }
        });
    }
}
