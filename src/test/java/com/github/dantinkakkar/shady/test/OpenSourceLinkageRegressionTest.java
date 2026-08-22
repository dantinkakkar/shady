package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import com.github.dantinkakkar.shady.LinkageHazardDetector.LinkageHazard;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
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
    void catchesDaggerGuavaIssue4658BeforeTheJvmFailsAtRuntime() throws Exception {
        // Reported 2025-03-25: https://github.com/google/dagger/issues/4658
        LinkageHazard predicted = assertReportedHazard(
                "google/dagger#4658",
                "dagger-spi-2.56.1.jar",
                "guava-32.1.2-jre.jar",
                "com.google.common.graph.Graphs",
                "reachableNodes(Lcom/google/common/graph/Graph;Ljava/lang/Object;)"
                        + "Lcom/google/common/collect/ImmutableSet;",
                "dagger.internal.codegen.extension.DaggerGraphs.unreachableNodes(");

        NoSuchMethodError actual = reproduceDaggerGuavaIssue4658();
        assertTrue(actual.getMessage().contains(predicted.getTargetClassName()));
        assertTrue(actual.getMessage().contains("reachableNodes"));
        assertTrue(Arrays.stream(actual.getStackTrace()).anyMatch(frame ->
                        "dagger.internal.codegen.extension.DaggerGraphs"
                                .equals(frame.getClassName())
                                && "unreachableNodes".equals(frame.getMethodName())),
                "The runtime failure should originate at the call site Shady analyzed");

        System.out.println("[Runtime proof] The JVM failed exactly as Shady predicted:");
        actual.printStackTrace(System.out);
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

    @Test
    void catchesLogbackSlf4jApiMismatchInFlinkApplications() {
        // Exploratory 2026-08-22: Apache Flink 1.20.1 declares slf4j-api:1.7.36 as a direct
        // dependency, overriding any newer transitive requirement.  logback-classic 1.5.x was
        // compiled against SLF4J 2.x and calls methods on org.slf4j.event.LoggingEvent (e.g.
        // getCallerBoundary, getMarkers, getKeyValuePairs) that simply do not exist in 1.7.x.
        // Any Flink project that adds logback-classic for structured logging silently carries
        // this hazard until a structured-logging code path executes.
        assertReportedHazard(
                "apache/flink#logback-slf4j-2026",
                "logback-classic-1.5.18.jar",
                "slf4j-api-1.7.36.jar",
                "org.slf4j.event.LoggingEvent",
                "getCallerBoundary()Ljava/lang/String;",
                "ch.qos.logback.classic.Logger.log(",
                "logback-core-1.5.18.jar");
    }

    @Test
    void catchesHibernateOrmJakartaPersistenceMismatch() {
        // Exploratory 2026-08-22: Hibernate ORM 6.2+ targets the jakarta.persistence-api 3.1 API
        // (Jakarta EE 10).  EE 9.x platforms still ship jakarta.persistence-api 3.0.x, which is
        // missing the two-argument constructors EntityNotFoundException(String, Exception) and
        // NonUniqueResultException(String, Exception) that Hibernate 6.6 calls inside
        // ExceptionConverterImpl.  A Maven or Gradle project that imports a Jakarta EE 9.x BOM
        // while pulling in Hibernate 6.6.x will hit NoSuchMethodError the first time an entity
        // lookup fails or a non-unique query result is returned.
        assertReportedHazard(
                "hibernate/hibernate-orm#jakarta-persistence-3.0-2026",
                "hibernate-core-6.6.13.Final.jar",
                "jakarta.persistence-api-3.0.0.jar",
                "jakarta.persistence.EntityNotFoundException",
                "<init>(Ljava/lang/String;Ljava/lang/Exception;)V",
                "org.hibernate.internal.ExceptionConverterImpl.convert(");
    }

    @Test
    void catchesSpringSecuritySpelBeanReferenceGetName() {
        // Exploratory 2026-08-22: Spring Security 6.4 calls
        // org.springframework.expression.spel.ast.BeanReference.getName(), a method added in
        // Spring Framework 6.2.  A Gradle project that uses
        //   enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.x")
        // will have spring-expression pinned at the 6.1.x series while spring-security-core is
        // resolved at 6.4.x from a direct dependency, silently combining incompatible artifacts.
        // The hazard fires when a @PreAuthorize expression containing a bean reference is
        // evaluated for the first time.
        assertReportedHazard(
                "spring-projects/spring-security#spel-beanref-2026",
                "spring-security-core-6.4.5.jar",
                "spring-expression-6.1.21.jar",
                "org.springframework.expression.spel.ast.BeanReference",
                "getName()Ljava/lang/String;",
                "org.springframework.security.aot.hint"
                        + ".PrePostAuthorizeExpressionBeanHintsRegistrar.resolveBeanNames(",
                "spring-core-6.1.21.jar");
    }

    @Test
    void catchesSpringSecurityPropertyPlaceholderHelperConstructor() {
        // Exploratory 2026-08-22: Spring Security 6.4 also calls a five-argument
        // PropertyPlaceholderHelper constructor added in Spring Core 6.2.  Same root cause as
        // the SpEL BeanReference finding above: a Spring Boot 3.2.x enforced platform pins
        // spring-core at 6.1.x while spring-security-core 6.4.x is used directly, producing
        // two distinct NoSuchMethodError traps in the same version-skew scenario.
        assertReportedHazard(
                "spring-projects/spring-security#placeholder-helper-2026",
                "spring-security-core-6.4.5.jar",
                "spring-core-6.1.21.jar",
                "org.springframework.util.PropertyPlaceholderHelper",
                "<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                        + "Ljava/lang/Character;Z)V",
                "org.springframework.security.core.annotation"
                        + ".ExpressionTemplateSecurityAnnotationScanner.resolvePlaceholders(");
    }

    @Test
    void catchesJacksonDatabind218BufferRecyclerMismatch() {
        // Exploratory 2026-08-22: jackson-databind 2.18 added calls to
        // BufferRecycler.releaseToPool() and ByteArrayBuilder.getClearAndRelease(), new resource-
        // management methods introduced in jackson-core 2.16.  Any project that uses
        //   enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.x")
        // will have jackson-core locked at the 2.15.x series managed by that BOM, while a direct
        // dependency on jackson-databind 2.18.x creates the incompatibility.  The hazard fires on
        // any ObjectMapper.writeValueAsString / writeValueAsBytes call.
        assertReportedHazard(
                "FasterXML/jackson-databind#bufferrecycler-2026",
                "jackson-databind-2.18.3.jar",
                "jackson-core-2.15.4.jar",
                "com.fasterxml.jackson.core.util.BufferRecycler",
                "releaseToPool()V",
                "com.fasterxml.jackson.databind.ObjectMapper.writeValueAsString(",
                "jackson-annotations-2.15.4.jar");
    }

    private LinkageHazard assertReportedHazard(String issue, String callerJarName,
                                               String targetJarName, String targetClass,
                                               String methodSignature, String callerPrefix,
                                               String... supportingJarNames) {
        Path callerJar = findFixtureJar(callerJarName);
        Path targetJar = findFixtureJar(targetJarName);

        StringBuilder fixtureClasspath = new StringBuilder()
                .append(callerJar)
                .append(File.pathSeparator)
                .append(targetJar);
        for (String supportingJarName : supportingJarNames) {
            fixtureClasspath.append(File.pathSeparator)
                    .append(findFixtureJar(supportingJarName));
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

    /** Execute the public #4658 artifact pair in isolation, then enter the reported call site. */
    private NoSuchMethodError reproduceDaggerGuavaIssue4658() throws Exception {
        URL[] incompatibleDaggerRuntime = {
                findClasspathEntry("dagger-spi-2.56.1.jar").toUri().toURL(),
                findClasspathEntry("guava-32.1.2-jre.jar").toUri().toURL()
        };

        try (URLClassLoader loader = new URLClassLoader(
                incompatibleDaggerRuntime, ClassLoader.getPlatformClassLoader())) {
            Class<?> graphBuilderClass = loader.loadClass(
                    "com.google.common.graph.GraphBuilder");
            Object graphBuilder = graphBuilderClass.getMethod("directed").invoke(null);
            Object graph = graphBuilderClass.getMethod("build").invoke(graphBuilder);
            Class<?> mutableGraphClass = loader.loadClass("com.google.common.graph.MutableGraph");
            mutableGraphClass.getMethod("addNode", Object.class).invoke(graph, "root");

            Class<?> graphClass = loader.loadClass("com.google.common.graph.Graph");
            Class<?> daggerGraphsClass = loader.loadClass(
                    "dagger.internal.codegen.extension.DaggerGraphs");
            java.lang.reflect.Method unreachableNodes = daggerGraphsClass.getDeclaredMethod(
                    "unreachableNodes", graphClass, Object.class);
            unreachableNodes.setAccessible(true);

            InvocationTargetException invocation = assertThrows(InvocationTargetException.class,
                    () -> unreachableNodes.invoke(null, graph, "root"));
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

    /**
     * Locates a fixture JAR that cannot live on the live test classpath (e.g. it would cause
     * a version conflict that breaks the test process). The Maven dependency plugin copies such
     * JARs to {@code target/fixture-jars} before tests run; the directory is communicated via
     * the {@code shady.fixture.jar.dir} system property set in the Surefire configuration.
     */
    private static Path findFixtureJar(String fileName) {
        // 1. Classpath first — works for JARs that are safe to put there.
        String[] entries = System.getProperty("java.class.path", "")
                .split(Pattern.quote(File.pathSeparator));
        for (String entry : entries) {
            Path path = Path.of(entry).toAbsolutePath().normalize();
            if (fileName.equals(path.getFileName().toString())) {
                return path;
            }
        }
        // 2. Fixture directory populated by maven-dependency-plugin:copy.
        String fixtureDirProp = System.getProperty("shady.fixture.jar.dir");
        if (fixtureDirProp != null) {
            Path jar = Path.of(fixtureDirProp).resolve(fileName);
            if (Files.exists(jar)) {
                return jar;
            }
        }
        throw new AssertionError(
                "Expected test fixture on classpath or in fixture directory: " + fileName
                + " (set shady.fixture.jar.dir to target/fixture-jars)");
    }
}
