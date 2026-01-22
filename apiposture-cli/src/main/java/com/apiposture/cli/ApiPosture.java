package com.apiposture.cli;

import com.apiposture.cli.commands.LicenseCommand;
import com.apiposture.cli.commands.ScanCommand;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Main entry point for ApiPosture CLI.
 */
@Command(
        name = "apiposture",
        description = "Security inspection CLI for Spring Boot/Spring Security APIs",
        version = "1.0.0-SNAPSHOT",
        mixinStandardHelpOptions = true,
        subcommands = {
                ScanCommand.class,
                LicenseCommand.class,
                CommandLine.HelpCommand.class
        }
)
public class ApiPosture implements Runnable {

    @Option(names = {"--no-color"}, description = "Disable colored output")
    boolean noColor;

    @Option(names = {"--no-icons"}, description = "Disable icons/emojis in output")
    boolean noIcons;

    public static void main(String[] args) {
        // Initialize ANSI console for Windows support
        AnsiConsole.systemInstall();

        try {
            int exitCode = new CommandLine(new ApiPosture())
                    .setCaseInsensitiveEnumValuesAllowed(true)
                    .execute(args);
            System.exit(exitCode);
        } finally {
            AnsiConsole.systemUninstall();
        }
    }

    @Override
    public void run() {
        // If no subcommand is specified, show help
        CommandLine.usage(this, System.out);
    }

    public boolean isNoColor() {
        return noColor;
    }

    public boolean isNoIcons() {
        return noIcons;
    }
}
