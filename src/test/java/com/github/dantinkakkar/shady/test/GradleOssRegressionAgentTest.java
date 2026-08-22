package com.github.dantinkakkar.shady.test;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Black-box proof of the jackson-databind 2.18 / jackson-core 2.15 linkage hazard discovered
 * by Shady, demonstrated via a <em>Gradle</em>-based application.
 *
 * <p>The fixture project ({@code src/test/fixtures/gradle-jackson-app}) uses Gradle's
 * {@code enforcedPlatform} with {@code org.springframework.boot:spring-boot-dependencies:3.2.12}.
 * That BOM locks {@code jackson-core} at {@code 2.15.4} as a strict constraint even though
 * {@code jackson-databind:2.18.3} (the direct dependency) transitively requires
 * {@code jackson-core:2.18.3}.  The resulting dependency graph contains both JARs at
 * incompatible versions, exactly as Shady's static analysis predicts:
 * {@code ObjectMapper.writeValueAsString} calls {@code BufferRecycler.releaseToPool()}, a method
 * absent from {@code jackson-core} 2.15.x.
 */
class GradleOssRegressionAgentTest {

    private static final String CALLER =
            "com.fasterxml.jackson.databind.ObjectMapper"
                    + ".writeValueAsString(java.lang.Object): java.lang.String";
    private static final String EXPECTED =
            "com.fasterxml.jackson.core.util.BufferRecycler.releaseToPool(): void";

    @Test
    void catchesJacksonBufferRecyclerHazardViaGradleEnforcedPlatform() throws Exception {
        Path projectRoot = Path.of(System.getProperty("user.dir"));
        Path fixture = projectRoot.resolve("src/test/fixtures/gradle-jackson-app");

        // 1. Build the fixture with Gradle and resolve the runtime classpath.
        ProcessResult build = run(180, fixture,
                fixture.resolve(gradleExecutable()).toString(),
                "--no-daemon", "--quiet", "compileJava", "writeRuntimeClasspath");
        assertEquals(0, build.exitCode,
                () -> "Could not build the Gradle Jackson application:\n" + build.output);

        Path runtimeClasspathFile = fixture.resolve("build/runtime-classpath.txt");
        assertTrue(Files.exists(runtimeClasspathFile),
                "writeRuntimeClasspath task must produce build/runtime-classpath.txt");

        String dependencies = Files.readString(runtimeClasspathFile, StandardCharsets.UTF_8).trim();
        assertTrue(dependencies.contains("jackson-databind-2.18.3.jar"),
                "Gradle must resolve jackson-databind-2.18.3 from the direct dependency");
        assertTrue(dependencies.contains("jackson-core-2.15.4.jar"),
                "Gradle resolutionStrategy.force must pin jackson-core at 2.15.4");

        // 2. Run the application through the Shady agent.
        String classpath = fixture.resolve("build/classes/java/main")
                + File.pathSeparator + dependencies;
        ProcessResult app = run(60, projectRoot,
                javaExecutable().toString(),
                "-javaagent:" + findPackagedAgent(),
                "-cp", classpath,
                "shady.example.GradleJacksonApp");
        dump(app);

        // 3. Shady must warn before the NoSuchMethodError fires.
        assertTrue(app.exitCode != 0,
                "The incompatible Gradle dependency graph must fail at runtime");
        assertTrue(app.output.contains("Caller:   " + CALLER),
                "Shady must identify the exact calling method");
        assertTrue(app.output.contains("Expected: " + EXPECTED),
                "Shady must name the missing method");
        assertTrue(app.output.contains(
                "Actual:   no exact method in com.fasterxml.jackson.core.util.BufferRecycler"),
                "Shady must confirm the method is absent from the resolved JAR");
        assertTrue(app.output.contains("jackson-core-2.15.4.jar"),
                "Shady must cite the incompatible jackson-core JAR resolved by Gradle");
        assertTrue(app.output.contains("Impact:   this call will throw NoSuchMethodError"),
                "Shady must state the runtime impact");
        assertTrue(app.output.contains("java.lang.NoSuchMethodError"),
                "The JVM must confirm the prediction by actually throwing NoSuchMethodError");

        int warning = app.output.indexOf("Caller:   " + CALLER);
        int failure = app.output.indexOf("java.lang.NoSuchMethodError");
        assertTrue(warning >= 0 && warning < failure,
                "Shady must report the hazard before the application execution reaches it");
    }

    // -------------------------------------------------------------------------
    // Helpers (mirrored from CurrentOssRegressionAgentTest)
    // -------------------------------------------------------------------------

    private static ProcessResult run(long timeoutSeconds, Path directory,
                                     String... command) throws Exception {
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        AtomicReference<IOException> readFailure = new AtomicReference<>();
        Thread outputReader = new Thread(() -> {
            try {
                process.getInputStream().transferTo(output);
            } catch (IOException e) {
                readFailure.set(e);
            }
        }, "shady-test-process-output");
        outputReader.setDaemon(true);
        outputReader.start();

        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            outputReader.join(TimeUnit.SECONDS.toMillis(5));
            throw new AssertionError("Process did not exit within " + timeoutSeconds + " seconds");
        }
        outputReader.join(TimeUnit.SECONDS.toMillis(10));
        if (outputReader.isAlive()) {
            throw new AssertionError("Could not finish reading process output");
        }
        if (readFailure.get() != null) {
            throw new IOException("Could not read process output", readFailure.get());
        }
        return new ProcessResult(process.exitValue(), output.toString(StandardCharsets.UTF_8));
    }

    private static String gradleExecutable() {
        String wrapper = System.getProperty("os.name").toLowerCase().contains("win")
                ? "gradlew.bat" : "gradlew";
        return wrapper;
    }

    private static Path javaExecutable() {
        String executable = System.getProperty("os.name").toLowerCase().contains("win")
                ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", executable);
    }

    private static Path findPackagedAgent() throws IOException {
        Path target = Path.of(System.getProperty("user.dir"), "target");
        try (Stream<Path> files = Files.list(target)) {
            return files
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().startsWith("shady-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().startsWith("original-"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError(
                            "Packaged agent JAR was not found under " + target));
        }
    }

    private static void dump(ProcessResult app) {
        System.out.println("=== GRADLE JACKSON APPLICATION (exit " + app.exitCode + ") ===");
        System.out.print(app.output);
        System.out.println("=== END GRADLE JACKSON APPLICATION ===");
    }

    private static final class ProcessResult {
        private final int exitCode;
        private final String output;

        private ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
