package com.github.dantinkakkar.shady.test;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Black-box proof using a clean Maven application and its ordinary process classpath. */
class CurrentOssRegressionAgentTest {

    private static final String CALLER =
            "org.apache.commons.text.translate.NumericEntityEscaper"
                    + ".<init>(int, int, boolean): void";
    private static final String EXPECTED =
            "org.apache.commons.lang3.Range.of(java.lang.Comparable, java.lang.Comparable): "
                    + "org.apache.commons.lang3.Range";

    @Test
    void catchesLatestCalciteRegressionBeforeNormalApplicationCodeHitsIt() throws Exception {
        Path projectRoot = Path.of(System.getProperty("user.dir"));
        Path fixture = projectRoot.resolve("src/test/fixtures/current-calcite-app");
        Path runtimeClasspath = fixture.resolve("target/runtime-classpath.txt");

        ProcessResult build = run(120, fixture,
                mavenExecutable(), "-B", "-q", "compile",
                "dependency:build-classpath",
                "-Dmdep.outputFile=" + runtimeClasspath);
        assertEquals(0, build.exitCode,
                () -> "Could not build the current Calcite application:\n" + build.output);

        String dependencies = Files.readString(runtimeClasspath, StandardCharsets.UTF_8).trim();
        assertTrue(dependencies.contains("calcite-core-1.42.0.jar"));
        assertTrue(dependencies.contains("commons-text-1.11.0.jar"));
        assertTrue(dependencies.contains("commons-lang3-3.1.jar"));

        String classpath = fixture.resolve("target/classes")
                + File.pathSeparator + dependencies;
        ProcessResult app = run(60, projectRoot,
                javaExecutable().toString(), "-javaagent:" + findPackagedAgent(),
                "-cp", classpath, "shady.example.CurrentCalciteApp");
        dump(app);

        assertTrue(app.exitCode != 0, "The incompatible current graph must fail at runtime");
        assertTrue(app.output.contains("Caller:   " + CALLER));
        assertTrue(app.output.contains("Expected: " + EXPECTED));
        assertTrue(app.output.contains(
                "Actual:   no exact method in org.apache.commons.lang3.Range"));
        assertTrue(app.output.contains("commons-lang3-3.1.jar"));
        assertTrue(app.output.contains("Impact:   this call will throw NoSuchMethodError"));
        assertTrue(app.output.contains("java.lang.NoSuchMethodError"));
        assertTrue(app.output.contains("NumericEntityEscaper.<init>(NumericEntityEscaper.java:97)"));
        assertTrue(app.output.contains("SqlFunctions.containsSubstr"));
        assertTrue(app.output.contains("CurrentCalciteApp.main"));

        int warning = app.output.indexOf("Caller:   " + CALLER);
        int failure = app.output.indexOf("java.lang.NoSuchMethodError");
        assertTrue(warning >= 0 && warning < failure,
                "Shady must report the exact hazard before application execution reaches it");
    }

    private static ProcessResult run(long timeoutSeconds, Path directory,
                                     String... command) throws Exception {
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start();
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("Process did not exit within " + timeoutSeconds + " seconds");
        }
        return new ProcessResult(process.exitValue(),
                new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
    }

    private static String mavenExecutable() {
        return System.getProperty("os.name").toLowerCase().contains("win")
                ? "mvn.cmd" : "mvn";
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
        System.out.println("=== CURRENT CALCITE APPLICATION (exit " + app.exitCode + ") ===");
        System.out.print(app.output);
        System.out.println("=== END CURRENT CALCITE APPLICATION ===");
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
