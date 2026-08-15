package com.github.dantinkakkar.shady.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Black-box acceptance tests for the packaged Java agent.
 *
 * <p>The consumer is compiled against library v2, which provides {@code decode(String, int)}.
 * At runtime it is paired with either v1, where that method is absent, or the compatible v2 JAR.
 * The consumer and library classes have different FQNs, so the broken case contains no duplicate
 * class and mirrors the shape of the Netty mismatch.</p>
 */
class HandmadeArtifactAgentTest {

    private static final String CALLER =
            "handmade.app.Consumer.main(java.lang.String[]): void";
    private static final String EXPECTED =
            "handmade.lib.Parser.decode(java.lang.String, int): java.lang.String";
    private static final String AVAILABLE =
            "handmade.lib.Parser.decode(java.lang.String): java.lang.String";

    @TempDir
    Path tempDir;

    private Path agentJar;
    private Path consumerJar;
    private Path libraryV1Jar;
    private Path libraryV2Jar;

    @BeforeEach
    void buildHandmadeArtifacts() throws IOException {
        agentJar = findPackagedAgent();

        libraryV1Jar = compileJar(
                "handmade-library-v1.jar",
                Map.of("handmade/lib/Parser.java", libraryV1Source()),
                List.of());
        libraryV2Jar = compileJar(
                "handmade-library-v2.jar",
                Map.of("handmade/lib/Parser.java", libraryV2Source()),
                List.of());
        consumerJar = compileJar(
                "handmade-consumer.jar",
                Map.of("handmade/app/Consumer.java", consumerSource()),
                List.of(libraryV2Jar));
    }

    @Test
    void agentReportsTheExactHazardBeforeTheJvmFails() throws Exception {
        AgentRun run = runWithAgent(libraryV1Jar);
        dump("BROKEN HANDMADE ARTIFACTS", run);

        assertTrue(run.exitCode != 0, "The incompatible runtime should fail linkage");
        assertTrue(run.output.contains("Indexed 2 effective classes and found 0 duplicate FQNs"));
        assertTrue(run.output.contains("Caller:   " + CALLER));
        assertTrue(run.output.contains("Expected: " + EXPECTED));
        assertTrue(run.output.contains("Actual:   no exact method in handmade.lib.Parser"));
        assertTrue(run.output.contains("From:     "
                + libraryV1Jar.toAbsolutePath().normalize()));
        assertTrue(run.output.contains("Available same-name methods:"));
        assertTrue(run.output.contains("    - " + AVAILABLE));
        assertTrue(run.output.contains("Impact:   this call will throw NoSuchMethodError"));
        assertTrue(run.output.contains("java.lang.NoSuchMethodError"));

        int warning = run.output.indexOf("[Shady] WARNING: Linkage hazard detected!");
        int linkageFailure = run.output.indexOf("java.lang.NoSuchMethodError");
        assertTrue(warning >= 0 && warning < linkageFailure,
                "Shady should report the latent hazard before the JVM reaches it");
    }

    @Test
    void compatibleArtifactRunsCleanlyWithoutAWarning() throws Exception {
        AgentRun run = runWithAgent(libraryV2Jar);
        dump("COMPATIBLE HANDMADE ARTIFACTS", run);

        assertEquals(0, run.exitCode);
        assertTrue(run.output.contains("Indexed 2 effective classes and found 0 duplicate FQNs"));
        assertTrue(run.output.contains("Linkage analysis complete: 0 hazard(s)"));
        assertTrue(run.output.contains("RESULT=payload"));
        assertFalse(run.output.contains("Expected: " + EXPECTED));
        assertFalse(run.output.contains("Linkage hazard detected"));
    }

    private AgentRun runWithAgent(Path runtimeLibrary) throws Exception {
        String classpath = consumerJar + File.pathSeparator + runtimeLibrary;
        Process process = new ProcessBuilder(
                javaExecutable().toString(),
                "-javaagent:" + agentJar,
                "-cp", classpath,
                "handmade.app.Consumer")
                .redirectErrorStream(true)
                .start();

        if (!process.waitFor(20, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("Handmade fixture JVM did not exit within 20 seconds");
        }

        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new AgentRun(process.exitValue(), output);
    }

    private Path compileJar(String jarName, Map<String, String> sources,
                            List<Path> classpath) throws IOException {
        Path fixtureRoot = tempDir.resolve(jarName.substring(0, jarName.length() - 4));
        Path sourceRoot = fixtureRoot.resolve("src");
        Path classesRoot = fixtureRoot.resolve("classes");
        Files.createDirectories(sourceRoot);
        Files.createDirectories(classesRoot);

        List<String> arguments = new ArrayList<>();
        arguments.add("-source");
        arguments.add("11");
        arguments.add("-target");
        arguments.add("11");
        arguments.add("-d");
        arguments.add(classesRoot.toString());
        if (!classpath.isEmpty()) {
            arguments.add("-classpath");
            arguments.add(joinClasspath(classpath));
        }

        for (Map.Entry<String, String> source : sources.entrySet()) {
            Path sourceFile = sourceRoot.resolve(source.getKey());
            Files.createDirectories(sourceFile.getParent());
            Files.writeString(sourceFile, source.getValue(), StandardCharsets.UTF_8);
            arguments.add(sourceFile.toString());
        }

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new AssertionError("Acceptance test requires a JDK, not a JRE");
        }
        ByteArrayOutputStream compilerOutput = new ByteArrayOutputStream();
        int result = compiler.run(
                null, compilerOutput, compilerOutput, arguments.toArray(new String[0]));
        assertEquals(0, result, () -> "Fixture compilation failed:\n"
                + new String(compilerOutput.toByteArray(), StandardCharsets.UTF_8));

        Path jar = tempDir.resolve(jarName);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar));
             Stream<Path> classFiles = Files.walk(classesRoot)) {
            classFiles.filter(Files::isRegularFile)
                    .sorted()
                    .forEach(classFile -> writeClass(output, classesRoot, classFile));
        }
        return jar;
    }

    private static void writeClass(JarOutputStream output, Path classesRoot, Path classFile) {
        String entryName = classesRoot.relativize(classFile)
                .toString()
                .replace(File.separatorChar, '/');
        JarEntry entry = new JarEntry(entryName);
        entry.setTime(0L);
        try {
            output.putNextEntry(entry);
            Files.copy(classFile, output);
            output.closeEntry();
        } catch (IOException e) {
            throw new IllegalStateException("Could not write fixture class " + entryName, e);
        }
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

    private static Path javaExecutable() {
        String executable = System.getProperty("os.name").toLowerCase().contains("win")
                ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", executable);
    }

    private static String joinClasspath(List<Path> entries) {
        StringBuilder value = new StringBuilder();
        for (Path entry : entries) {
            if (value.length() > 0) {
                value.append(File.pathSeparator);
            }
            value.append(entry);
        }
        return value.toString();
    }

    private static void dump(String label, AgentRun run) {
        System.out.println("=== " + label + " (exit " + run.exitCode + ") ===");
        System.out.print(run.output);
        System.out.println("=== END " + label + " ===");
    }

    private static String libraryV1Source() {
        return "package handmade.lib;\n"
                + "public final class Parser {\n"
                + "    private Parser() {}\n"
                + "    public static String decode(String value) { return value; }\n"
                + "}\n";
    }

    private static String libraryV2Source() {
        return "package handmade.lib;\n"
                + "public final class Parser {\n"
                + "    private Parser() {}\n"
                + "    public static String decode(String value, int limit) { return value; }\n"
                + "}\n";
    }

    private static String consumerSource() {
        return "package handmade.app;\n"
                + "import handmade.lib.Parser;\n"
                + "public final class Consumer {\n"
                + "    private Consumer() {}\n"
                + "    public static void main(String[] args) {\n"
                + "        System.out.println(\"APP_STARTED\");\n"
                + "        System.out.println(\"RESULT=\" + Parser.decode(\"payload\", 64));\n"
                + "    }\n"
                + "}\n";
    }

    private static final class AgentRun {
        private final int exitCode;
        private final String output;

        private AgentRun(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
