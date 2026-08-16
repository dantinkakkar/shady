package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import com.github.dantinkakkar.shady.LinkageHazardDetector.LinkageHazard;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Reproduces method-linkage failures reported by independent open-source projects.
 * The dependencies are test-scoped and intentionally incompatible; they are never shipped.
 */
class OpenSourceLinkageRegressionTest {

    @Test
    void catchesJacksonDatabindIssue3429() {
        // https://github.com/FasterXML/jackson-databind/issues/3429
        assertReportedHazard(
                "FasterXML/jackson-databind#3429",
                "jackson-databind-2.13.2.jar",
                "jackson-core-2.11.4.jar",
                "com.fasterxml.jackson.core.JsonParser",
                "getReadCapabilities()"
                        + "Lcom/fasterxml/jackson/core/util/JacksonFeatureSet;",
                null);
    }

    @Test
    void catchesLettuceReactorIssue9147() {
        // https://github.com/open-telemetry/opentelemetry-java-instrumentation/issues/9147
        assertReportedHazard(
                "open-telemetry/opentelemetry-java-instrumentation#9147",
                "lettuce-core-6.1.10.RELEASE.jar",
                "reactor-core-3.5.3.jar",
                "reactor.core.publisher.Mono",
                "subscriberContext()Lreactor/core/publisher/Mono;",
                "io.lettuce.core.tracing.Tracing.getContext(");
    }

    @Test
    void catchesQuarkusLog4jIssue35428() {
        // https://github.com/quarkusio/quarkus/issues/35428
        assertReportedHazard(
                "quarkusio/quarkus#35428",
                "log4j-core-2.17.1.jar",
                "log4j-api-2.20.0.jar",
                "org.apache.logging.log4j.util.LoaderUtil",
                "getClassLoaders()[Ljava/lang/ClassLoader;",
                null);
    }

    private void assertReportedHazard(String issue, String callerJarName, String targetJarName,
                                      String targetClass, String methodSignature,
                                      String callerPrefix) {
        Path callerJar = findClasspathEntry(callerJarName);
        Path targetJar = findClasspathEntry(targetJarName);

        System.out.println("=== OPEN-SOURCE REGRESSION: " + issue + " ===");
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath(callerJar + File.pathSeparator + targetJar);

        assertFalse(detector.getDuplicateClasses().containsKey(targetClass),
                "The reported failure must not depend on a duplicate target class");

        LinkageHazard hazard = detector.getDetectedHazards().stream()
                .filter(candidate -> targetClass.equals(candidate.getTargetClassName()))
                .filter(candidate -> methodSignature.equals(candidate.getMethodSignature()))
                .filter(candidate -> callerPrefix == null
                        || candidate.getCallerSignature().startsWith(callerPrefix))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Shady did not catch " + issue + "; hazards were "
                                + detector.getDetectedHazards()));

        assertEquals(targetJar.toAbsolutePath().normalize().toString(),
                hazard.getTargetLocation());
        System.out.println("[Shady test] Matched reported failure: " + hazard);
        System.out.println("=== END OPEN-SOURCE REGRESSION: " + issue + " ===");
    }

    private static Path findClasspathEntry(String fileName) {
        String[] entries = System.getProperty("java.class.path", "")
                .split(Pattern.quote(File.pathSeparator));
        for (String entry : entries) {
            Path path = Path.of(entry).toAbsolutePath().normalize();
            if (fileName.equals(path.getFileName().toString())) {
                return path;
            }
        }
        throw new AssertionError("Expected test fixture on classpath: " + fileName);
    }
}
