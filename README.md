# ApiPosture.Java

[![Build and Test](https://github.com/BlagoCuljak/ApiPosture.Java/actions/workflows/build.yml/badge.svg)](https://github.com/BlagoCuljak/ApiPosture.Java/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security inspection CLI for Spring Boot/Spring Security APIs using static source-code analysis.

ApiPosture scans your Spring Boot project and identifies authorization misconfigurations, security risks, and potential vulnerabilities - all without running your application.

## Features

- **Static Analysis** - Analyzes source code using JavaParser (no compilation required)
- **Spring Security Detection** - Recognizes `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@PermitAll`, `@DenyAll`
- **8 Security Rules** - Built-in rules covering exposure, consistency, privilege, and attack surface
- **Multiple Output Formats** - Terminal (colored), JSON, and Markdown
- **CI/CD Integration** - Exit codes and `--fail-on` option for pipeline integration

## Quick Start

### Prerequisites

- Java 21 or higher

### Download

Download the latest release:

```bash
curl -L -o apiposture.jar https://github.com/BlagoCuljak/ApiPosture.Java/releases/latest/download/apiposture.jar
```

Or download manually from the [Releases page](https://github.com/BlagoCuljak/ApiPosture.Java/releases).

### Build from Source (Optional)

Requires Maven 3.8+

```bash
git clone https://github.com/BlagoCuljak/ApiPosture.Java.git
cd ApiPosture.Java
mvn clean package -DskipTests
```

### Run

```bash
# Scan a Spring Boot project
java -jar apiposture.jar scan /path/to/spring-boot-project

# Output as JSON
java -jar apiposture.jar scan /path/to/project --output json

# Output as Markdown
java -jar apiposture.jar scan /path/to/project --output markdown -f report.md

# Fail if critical/high findings (for CI)
java -jar apiposture.jar scan /path/to/project --fail-on high
```

## Security Rules

| Rule | Name | Severity | Trigger |
|------|------|----------|---------|
| AP001 | Public without explicit intent | HIGH | Public endpoint without `@PermitAll` |
| AP002 | PermitAll on write operation | HIGH | `@PermitAll` on POST/PUT/DELETE/PATCH |
| AP003 | Controller/method conflict | MEDIUM | Method `@PermitAll` overrides class auth |
| AP004 | Missing auth on writes | CRITICAL | Public POST/PUT/DELETE without auth |
| AP005 | Excessive role access | LOW | >3 roles on single endpoint |
| AP006 | Weak role naming | LOW | Generic roles like "User", "Admin" |
| AP007 | Sensitive route keywords | MEDIUM | admin/debug/export in public routes |
| AP008 | Controller without auth | HIGH | Controller with no security annotations |

## CLI Options

```
Usage: apiposture scan [OPTIONS] [PATH]

Arguments:
  PATH                      Path to the project to scan (default: .)

Options:
  -o, --output <format>     Output format: terminal, json, markdown (default: terminal)
  -f, --output-file <path>  Write output to file
      --severity <level>    Minimum severity: info, low, medium, high, critical
      --fail-on <level>     Exit code 1 if findings >= severity (for CI)
      --sort-by <field>     Sort by: severity, route, method, classification
      --classification      Filter by: public, authenticated, role-restricted, policy-restricted
      --method              Filter by HTTP methods: GET, POST, PUT, DELETE, PATCH
      --exclude             Glob patterns to exclude
      --disable-rule        Disable rules by ID (e.g., AP001)
      --no-color            Disable colored output
      --no-icons            Disable icons in output
  -h, --help                Show this help message
  -V, --version             Print version information
```

## Sample Output

```
ApiPosture Security Scan Report
================================

Project: /path/to/spring-boot-project
Files scanned: 12
Duration: 1.23s

Endpoints found: 15
Findings: 7

  CRITICAL: 2
  HIGH: 3
  MEDIUM: 1
  LOW: 1

--- Findings ---

CRITICAL [AP004] Missing authorization on write operation
   Endpoint '/api/products' allows unauthenticated write operations: POST
   at /src/main/java/com/example/ProductsController.java:24
   Recommendation: Add @PreAuthorize, @Secured, or @RolesAllowed to restrict write access

HIGH [AP001] Public without explicit intent
   Endpoint '/api/products' is publicly accessible without explicit @PermitAll annotation
   at /src/main/java/com/example/ProductsController.java:18
   Recommendation: Add @PermitAll to explicitly indicate public access, or add appropriate security annotations
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Download ApiPosture
  run: curl -L -o apiposture.jar https://github.com/BlagoCuljak/ApiPosture.Java/releases/latest/download/apiposture.jar

- name: Run ApiPosture Security Scan
  run: java -jar apiposture.jar scan . --fail-on high --output json -f security-report.json

- name: Upload Security Report
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: security-report.json
```

### Exit Codes

- `0` - Scan completed successfully, no findings at or above `--fail-on` level
- `1` - Scan completed with findings at or above `--fail-on` level, or error occurred

## Project Structure

```
ApiPosture.Java/
├── apiposture-core/          # Analysis engine
│   └── src/main/java/com/apiposture/core/
│       ├── models/           # Endpoint, Finding, AuthorizationInfo, enums
│       ├── analysis/         # ProjectAnalyzer, SourceFileLoader
│       ├── discovery/        # ControllerEndpointDiscoverer
│       ├── authorization/    # AnnotationAuthorizationExtractor
│       └── classification/   # SecurityClassifier
├── apiposture-rules/         # Security rules
│   └── src/main/java/com/apiposture/rules/
│       ├── SecurityRule.java
│       ├── RuleEngine.java
│       ├── exposure/         # AP001, AP002
│       ├── consistency/      # AP003, AP004
│       ├── privilege/        # AP005, AP006
│       └── surface/          # AP007, AP008
├── apiposture-cli/           # CLI application
│   └── src/main/java/com/apiposture/cli/
│       ├── ApiPosture.java   # Main entry point
│       ├── commands/         # ScanCommand, LicenseCommand
│       └── output/           # Terminal, JSON, Markdown formatters
└── samples/sample-spring-boot/  # Sample project for testing
```

## Dependencies

- [JavaParser](https://javaparser.org/) - Java source code parsing
- [Picocli](https://picocli.info/) - CLI framework
- [Jansi](https://github.com/fusesource/jansi) - ANSI color support
- [Jackson](https://github.com/FasterXML/jackson) - JSON processing
- [JUnit 5](https://junit.org/junit5/) + [AssertJ](https://assertj.github.io/doc/) - Testing

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [ApiPosture (.NET)](https://github.com/BlagoCuljak/ApiPosture) - Original .NET version for ASP.NET Core APIs
