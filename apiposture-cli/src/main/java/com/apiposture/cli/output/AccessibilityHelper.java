package com.apiposture.cli.output;

import com.apiposture.core.models.SecurityClassification;
import com.apiposture.core.models.Severity;

/**
 * Provides accessibility options for terminal output including
 * color-free and icon-free alternatives. Mirrors the .NET reference
 * implementation's auto-detection of NO_COLOR, TTY redirect, and
 * Windows legacy console environments.
 */
public final class AccessibilityHelper {

    private final boolean useColors;
    private final boolean useIcons;

    // Severity emoji icons
    private static final java.util.Map<Severity, String> SEVERITY_ICONS = new java.util.EnumMap<>(Severity.class);
    // Severity text fallbacks ([CRIT], [HIGH], ...)
    private static final java.util.Map<Severity, String> SEVERITY_LABELS = new java.util.EnumMap<>(Severity.class);
    // Classification emoji icons
    private static final java.util.Map<SecurityClassification, String> CLASSIFICATION_ICONS =
            new java.util.EnumMap<>(SecurityClassification.class);
    // Classification text fallbacks ([PUBLIC], [AUTH], ...)
    private static final java.util.Map<SecurityClassification, String> CLASSIFICATION_LABELS =
            new java.util.EnumMap<>(SecurityClassification.class);

    static {
        // Text-only labels (emoji removed — not reliably supported on Linux/server terminals)
        SEVERITY_LABELS.put(Severity.CRITICAL, "[CRIT]");
        SEVERITY_LABELS.put(Severity.HIGH,     "[HIGH]");
        SEVERITY_LABELS.put(Severity.MEDIUM,   "[MED]");
        SEVERITY_LABELS.put(Severity.LOW,      "[LOW]");
        SEVERITY_LABELS.put(Severity.INFO,     "[INFO]");

        CLASSIFICATION_LABELS.put(SecurityClassification.PUBLIC,            "[PUBLIC]");
        CLASSIFICATION_LABELS.put(SecurityClassification.AUTHENTICATED,     "[AUTH]");
        CLASSIFICATION_LABELS.put(SecurityClassification.ROLE_RESTRICTED,   "[ROLE]");
        CLASSIFICATION_LABELS.put(SecurityClassification.POLICY_RESTRICTED, "[POLICY]");
    }

    public AccessibilityHelper(boolean useColors, boolean useIcons) {
        this.useColors = useColors;
        this.useIcons = useIcons;
    }

    /**
     * Creates an AccessibilityHelper from CLI flags, applying environment-based
     * auto-detection when the flags have not already forced a value.
     */
    public static AccessibilityHelper create(boolean noColorFlag, boolean noIconsFlag) {
        boolean useColors = determineUseColors(noColorFlag);
        boolean useIcons = determineUseIcons(noIconsFlag);
        return new AccessibilityHelper(useColors, useIcons);
    }

    private static boolean determineUseColors(boolean noColorFlag) {
        if (noColorFlag) return false;
        // NO_COLOR environment variable (https://no-color.org/)
        String noColor = System.getenv("NO_COLOR");
        if (noColor != null && !noColor.isEmpty()) return false;
        // Disable colors when stdout is not a TTY (redirected output)
        if (System.console() == null) return false;
        return true;
    }

    private static boolean determineUseIcons(boolean noIconsFlag) {
        // Emoji icons removed — terminal support is too unreliable across platforms.
        // Text labels are always used regardless of the noIcons flag.
        return false;
    }

    public boolean isUseColors() { return useColors; }
    public boolean isUseIcons()  { return useIcons; }

    public String getSeverityIndicator(Severity severity) {
        return SEVERITY_LABELS.getOrDefault(severity, "[?]");
    }

    public String getClassificationIndicator(SecurityClassification classification) {
        return CLASSIFICATION_LABELS.getOrDefault(classification, "[?]");
    }

    public String getSuccessIndicator()  { return "[OK]"; }
    public String getFailureIndicator()  { return "[FAIL]"; }
    public String getWarningIndicator()  { return "[WARN]"; }
}
