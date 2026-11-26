package com.apiposture.rules.secrets;

import com.apiposture.core.models.Finding;
import com.apiposture.core.models.Severity;
import com.apiposture.rules.RuleEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class HardcodedSecretRuleTest {

    private final HardcodedSecretRule rule = new HardcodedSecretRule();

    // Secrets are assembled at runtime so that no literal credential appears in the repository.
    private static String rep(String s, int n) {
        return s.repeat(n);
    }

    static Stream<Arguments> truePositives() {
        return Stream.of(
                Arguments.of("AWS access key", "AK" + "IA" + "7Q3ZK9PLM2XW4RT6"),
                Arguments.of("AWS temp key", "AS" + "IA" + "7Q3ZK9PLM2XW4RT6"),
                Arguments.of("GCP key", "AI" + "za" + "SyD4k" + rep("aB3", 10)),
                Arguments.of("GitHub ghp", "gh" + "p_" + rep("aB3dE6", 6)),
                Arguments.of("GitHub gho", "gh" + "o_" + rep("aB3dE6", 6)),
                Arguments.of("GitHub fine-grained", "github" + "_pat_" + rep("aB3dE6fG9h", 8) + "aB"),
                Arguments.of("GitLab PAT", "gl" + "pat-" + rep("k9Zt4", 5)),
                Arguments.of("Stripe live secret", "sk" + "_live_" + rep("k9Zt4Q", 5)),
                Arguments.of("Stripe live restricted", "rk" + "_live_" + rep("k9Zt4Q", 5)),
                Arguments.of("Slack token", "xo" + "xb-" + "8317462905-2947103856"),
                Arguments.of("Slack webhook", "https://hooks." + "slack.com/services/T" + "04K9ZQ7LM/B" + "07H2XW5RT/"
                        + rep("a1B2c3", 4)),
                Arguments.of("SendGrid key", "S" + "G." + rep("k9Zt4Q", 3) + "k9Zt." + rep("aB3dE6fG9h", 4) + "aB3"),
                Arguments.of("npm token", "np" + "m_" + rep("k9Zt4Q", 6)),
                Arguments.of("DigitalOcean token", "do" + "p_v1_" + rep("a1b2c3d4", 8)),
                Arguments.of("PEM RSA key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
                Arguments.of("PEM plain key", "-----BEGIN " + "PRIVATE KEY-----"),
                Arguments.of("PEM openssh key", "-----BEGIN " + "OPENSSH PRIVATE KEY-----")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("truePositives")
    void detectsProviderSecrets(String label, String secret) {
        String code = "class A {\n    String k = \"" + secret + "\";\n}\n";
        List<Finding> findings = rule.scanContent("A.java", code);

        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("AP201");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.location().lineNumber()).isEqualTo(2);
        assertThat(f.location().filePath()).isEqualTo("A.java");
        assertThat(f.message()).doesNotContain(secret);
        assertThat(f.message()).contains(secret.substring(0, 4) + "…");
    }

    @Test
    void oneFindingPerLinePerType() {
        String key = "AK" + "IA" + "7Q3ZK9PLM2XW4RT6";
        String other = "AK" + "IA" + "5Y8N2VBC4HD7JK3L";
        List<Finding> findings = rule.scanContent("a.properties", "k=" + key + "," + other + "\nz=" + key);
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(f -> f.location().lineNumber()).containsExactly(1, 2);
    }

    @Test
    void ignoresPlaceholders() {
        String[] values = {
                "AKIAIOSFODNN7EXAMPLE",
                "AK" + "IA" + "XXXXXXXXXXXXXXXX",
                "gh" + "p_" + rep("a", 20) + "dummy" + rep("b", 11),
                "sk" + "_live_" + "your_" + rep("k9Zt4Q", 5),
                "np" + "m_" + "fake" + rep("k9Zt4Q", 6),
                "np" + "m_" + "changeme" + rep("k9Zt4Q", 6),
                "gl" + "pat-" + "sample" + rep("k9Zt4", 5),
                "gl" + "pat-" + "placeholder" + rep("k9Zt4", 5),
                "gl" + "pat-" + "redacted" + rep("k9Zt4", 5),
                "gl" + "pat-" + "your-" + rep("k9Zt4", 5),
        };
        for (String v : values) {
            assertThat(rule.scanContent("A.java", "String k = \"" + v + "\";"))
                    .as(v).isEmpty();
        }
        assertThat(HardcodedSecretRule.isPlaceholder("a{{b")).isTrue();
        assertThat(HardcodedSecretRule.isPlaceholder("a<b")).isTrue();
        assertThat(HardcodedSecretRule.isPlaceholder("a>b")).isTrue();
        assertThat(HardcodedSecretRule.isPlaceholder("a${b")).isTrue();
        assertThat(HardcodedSecretRule.isPlaceholder("7Q3ZK9PLM2XW4RT6")).isFalse();
    }

    @Test
    void ignoresStripePublishableAndGenericPatterns() {
        String pk = "pk" + "_live_" + rep("k9Zt4Q", 5);
        String code = "String pk = \"" + pk + "\";\n"
                + "String password = \"hunter2hunter2\";\n"
                + "String token = \"abcdef1234567890abcdef\";\n"
                + "String h = \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc\";\n"
                + "String url = \"jdbc:mysql://u:pw@host/db\";\n";
        assertThat(rule.scanContent("A.java", code)).isEmpty();
    }

    @Test
    void doesNotMatchInsideLongerIdentifiers() {
        String embedded = "x" + "AK" + "IA" + "7Q3ZK9PLM2XW4RT6";
        String tooLong = "AK" + "IA" + "7Q3ZK9PLM2XW4RT6ABC";
        assertThat(rule.scanContent("A.java", "v = \"" + embedded + "\"")).isEmpty();
        assertThat(rule.scanContent("A.java", "v = \"" + tooLong + "\"")).isEmpty();
    }

    @Test
    void pathExclusions() {
        for (String p : new String[]{
                "src/test/java/A.java", "test/A.java", "tests/A.java", "spec/a.properties",
                "src/__tests__/a.java", "fixtures/a.java", "testdata/a.java", "samples/x/A.java",
                "examples/A.java", "docs/A.java", "node_modules/x/A.java", "vendor/A.java",
                "target/classes/A.java", "build/A.java", "src/main/java/FooTest.java",
                "src/main/java/FooTests.java", "src/main/java/FooIT.java", "yarn.lock"}) {
            assertThat(HardcodedSecretRule.isExcludedPath(Path.of(p))).as(p).isTrue();
        }
        for (String p : new String[]{"src/main/java/Foo.java", "src/main/resources/application.yml",
                ".env", "src/main/java/Contest.java"}) {
            assertThat(HardcodedSecretRule.isExcludedPath(Path.of(p))).as(p).isFalse();
        }
    }

    @Test
    void scanFileHonorsPathExclusionRelativeToRoot(@TempDir Path root) throws IOException {
        String secret = "AK" + "IA" + "7Q3ZK9PLM2XW4RT6";
        Path main = root.resolve("src/main/resources");
        Path tests = root.resolve("src/test/java");
        Files.createDirectories(main);
        Files.createDirectories(tests);
        Path cfg = main.resolve("application.properties");
        Files.writeString(cfg, "aws.key=" + secret + "\n");
        Path t = tests.resolve("FooTest.java");
        Files.writeString(t, "class FooTest { String k = \"" + secret + "\"; }");

        assertThat(rule.scanFile(root, cfg)).hasSize(1);
        assertThat(rule.scanFile(root, t)).isEmpty();
    }

    @Test
    void ruleEngineRespectsDisableAndSeverity(@TempDir Path root) throws IOException {
        Path f = root.resolve("Config.java");
        Files.writeString(f, "class Config { String k = \"" + "AK" + "IA" + "7Q3ZK9PLM2XW4RT6" + "\"; }");

        RuleEngine engine = new RuleEngine();
        assertThat(engine.evaluateSecrets(root, List.of(f))).hasSize(1);

        engine.setMinimumSeverity(Severity.CRITICAL);
        assertThat(engine.evaluateSecrets(root, List.of(f))).isEmpty();

        engine.setMinimumSeverity(Severity.INFO);
        engine.disableRule("AP201");
        assertThat(engine.evaluateSecrets(root, List.of(f))).isEmpty();
    }
}
