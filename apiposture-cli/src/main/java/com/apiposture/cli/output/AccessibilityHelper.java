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
        SEVERITY_ICONS.put(Severity.CRITICAL, "\u274c");        // Red X
        SEVERITY_ICONS.put(Severity.HIGH,     "\u26a0\ufe0f"); // Warning sign
        SEVERITY_ICONS.put(Severity.MEDIUM,   "\u26a1");        // Lightning bolt
        SEVERITY_ICONS.put(Severity.LOW,      "\u2139\ufe0f"); // Info
        SEVERITY_ICONS.put(Severity.INFO,     "\u2139\ufe0f"); // Info

        SEVERITY_LABELS.put(Severity.CRITICAL, "[CRIT]");
        SEVERITY_LABELS.put(Severity.HIGH,     "[HIGH]");
        SEVERITY_LABELS.put(Severity.MEDIUM,   "[MED]");
        SEVERITY_LABELS.put(Severity.LOW,      "[LOW]");
        SEVERITY_LABELS.put(Severity.INFO,     "[INFO]");

        CLASSIFICATION_ICONS.put(SecurityClassification.PUBLIC,           "\uD83D\uDD13"); // Unlocked
        CLASSIFICATION_ICONS.put(SecurityClassification.AUTHENTICATED,    "\uD83D\uDD10"); // Lock with key
        CLASSIFICATION_ICONS.put(SecurityClassification.ROLE_RESTRICTED,  "\uD83D\uDD12"); // Locked
        CLASSIFICATION_ICONS.put(SecurityClassification.POLICY_RESTRICTED,"\uD83D\uDEE1"); // Shield

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
        if (noIconsFlag) return false;
        // Auto-detect: disable icons on Windows legacy consoles (cmd.exe, PowerShell)
        // which cannot render emoji. Windows Terminal sets WT_SESSION and handles emoji fine.
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            String wtSession = System.getenv("WT_SESSION");
            if (wtSession == null || wtSession.isEmpty()) return false;
        }
        return true;
    }

    public boolean isUseColors() { return useColors; }
    public boolean isUseIcons()  { return useIcons; }

    public String getSeverityIndicator(Severity severity) {
        return useIcons
                ? SEVERITY_ICONS.getOrDefault(severity, "?")
                : SEVERITY_LABELS.getOrDefault(severity, "[?]");
    }

    public String getClassificationIndicator(SecurityClassification classification) {
        return useIcons
                ? CLASSIFICATION_ICONS.getOrDefault(classification, "?")
                : CLASSIFICATION_LABELS.getOrDefault(classification, "[?]");
    }

    public String getSuccessIndicator()  { return useIcons ? "\u2705" : "[OK]"; }
    public String getFailureIndicator()  { return useIcons ? "\u274c"  : "[FAIL]"; }
    public String getWarningIndicator()  { return useIcons ? "\u26a0\ufe0f" : "[WARN]"; }
}
