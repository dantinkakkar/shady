package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import com.github.dantinkakkar.shady.LinkageHazardDetector.LinkageHazard;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reproduces method-linkage failures reported by independent open-source projects.
 * The dependencies are test-scoped and intentionally incompatible; they are never shipped.
 */
class OpenSourceLinkageRegressionTest {

    @Test
    void catchesJacksonDatabindIssue3429BeforeTheJvmFailsAtRuntime() throws Exception {
        // https://github.com/FasterXML/jackson-databind/issues/3429
        LinkageHazard predicted = assertReportedHazard(
                "FasterXML/jackson-databind#3429",
                "jackson-databind-2.13.2.jar",
                "jackson-core-2.11.4.jar",
                "com.fasterxml.jackson.core.JsonParser",
                "getReadCapabilities()"
                        + "Lcom/fasterxml/jackson/core/util/JacksonFeatureSet;",
                null);

        NoSuchMethodError actual = reproduceJacksonDatabindIssue3429();
        assertTrue(actual.getMessage().contains(predicted.getTargetClassName()));
        assertTrue(actual.getMessage().contains("getReadCapabilities"));
        assertTrue(Arrays.stream(actual.getStackTrace()).anyMatch(frame ->
                        "com.fasterxml.jackson.databind.DeserializationContext"
                                .equals(frame.getClassName())),
                "The runtime failure should originate at the call site Shady analyzed");

        System.out.println("[Runtime proof] The JVM failed exactly as Shady predicted:");
        actual.printStackTrace(System.out);
    }

    @Test
    void catchesLettuceReactorIssue10997() {
        // https://github.com/open-telemetry/opentelemetry-java-instrumentation/issues/10997
        assertReportedHazard(
                "open-telemetry/opentelemetry-java-instrumentation#10997",
                "lettuce-core-6.1.10.RELEASE.jar",
                "reactor-core-3.5.3.jar",
                "reactor.core.publisher.Mono",
                "subscriberContext()Lreactor/core/publisher/Mono;",
                "io.lettuce.core.tracing.Tracing.getContext(",
                "reactive-streams-1.0.4.jar");
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

    @Test
    void catchesDaggerGuavaIssue4658() {
        // Reported 2025-03-25: https://github.com/google/dagger/issues/4658
        assertReportedHazard(
                "google/dagger#4658",
                "dagger-spi-2.56.1.jar",
                "guava-32.1.2-jre.jar",
                "com.google.common.graph.Graphs",
                "reachableNodes(Lcom/google/common/graph/Graph;Ljava/lang/Object;)"
                        + "Lcom/google/common/collect/ImmutableSet;",
                "dagger.internal.codegen.extension.DaggerGraphs.unreachableNodes(");
    }

    @Test
    void catchesKyuubiSnakeYamlIssue7114() {
        // Reported 2025-06-25: https://github.com/apache/kyuubi/issues/7114
        assertReportedHazard(
                "apache/kyuubi#7114",
                "kubernetes-client-5.12.2.jar",
                "snakeyaml-2.2.jar",
                "org.yaml.snakeyaml.constructor.SafeConstructor",
                "<init>()V",
                "io.fabric8.kubernetes.client.utils.Serialization.unmarshalYaml(");
    }

    @Test
    void catchesSpringdocSpringFrameworkIssue3041() {
        // Reported 2025-07-08: https://github.com/springdoc/springdoc-openapi/issues/3041
        assertReportedHazard(
                "springdoc/springdoc-openapi#3041",
                "springdoc-openapi-starter-common-2.5.0.jar",
                "spring-web-6.2.8.jar",
                "org.springframework.web.method.ControllerAdviceBean",
                "<init>(Ljava/lang/Object;)V",
                "org.springdoc.core.service.GenericResponseService.lambda$getGenericMapResponse$");
    }

    private LinkageHazard assertReportedHazard(String issue, String callerJarName,
                                               String targetJarName, String targetClass,
                                               String methodSignature, String callerPrefix,
                                               String... supportingJarNames) {
        Path callerJar = findClasspathEntry(callerJarName);
        Path targetJar = findClasspathEntry(targetJarName);

        StringBuilder fixtureClasspath = new StringBuilder()
                .append(callerJar)
                .append(File.pathSeparator)
                .append(targetJar);
        for (String supportingJarName : supportingJarNames) {
            fixtureClasspath.append(File.pathSeparator)
                    .append(findClasspathEntry(supportingJarName));
        }

        System.out.println("=== OPEN-SOURCE REGRESSION: " + issue + " ===");
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath(fixtureClasspath.toString());

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
        return hazard;
    }

    /**
     * Executes the ordinary Jackson API reported in #3429 inside an isolated class loader.
     * Isolation guarantees that the failure comes from exactly the three fixture JARs, rather
     * than from whichever Jackson versions Maven or Surefire happened to load first.
     */
    private NoSuchMethodError reproduceJacksonDatabindIssue3429() throws Exception {
        URL[] incompatibleJacksonRuntime = {
                findClasspathEntry("jackson-databind-2.13.2.jar").toUri().toURL(),
                findClasspathEntry("jackson-core-2.11.4.jar").toUri().toURL(),
                findClasspathEntry("jackson-annotations-2.13.2.jar").toUri().toURL()
        };

        try (URLClassLoader loader = new URLClassLoader(
                incompatibleJacksonRuntime, ClassLoader.getPlatformClassLoader())) {
            Class<?> objectMapperClass = loader.loadClass(
                    "com.fasterxml.jackson.databind.ObjectMapper");
            Object objectMapper = objectMapperClass.getConstructor().newInstance();

            InvocationTargetException invocation = assertThrows(InvocationTargetException.class,
                    () -> objectMapperClass.getMethod("readValue", String.class, Class.class)
                            .invoke(objectMapper, "{\"answer\":42}", Object.class));
            return assertInstanceOf(NoSuchMethodError.class, invocation.getCause());
        }
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
