package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.AgentConfig;
import com.github.dantinkakkar.shady.HazardReporter;
import com.github.dantinkakkar.shady.LinkageHazardDetector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class LinkageHazardDetectorTest {

    private static Path testJarsDir;
    private static Path testDirClassesDir;
    private static String originalClasspath;

    private ByteArrayOutputStream output;

    private LinkageHazardDetector createDetector() {
        output = new ByteArrayOutputStream();
        AgentConfig config = new AgentConfig(null);
        HazardReporter reporter = new HazardReporter(config, new PrintStream(output));
        return new LinkageHazardDetector(config, reporter, null);
    }

    @BeforeAll
    public static void setUp() throws Exception {
        testJarsDir = Files.createTempDirectory("shady-test-");

        createTestJarV1();
        createTestJarV2();
        createInnerClassJarV1();
        createInnerClassJarV2();
        createFieldJarV1();
        createFieldJarV2();

        testDirClassesDir = Files.createTempDirectory("shady-dirtest-");
        createDirTestJar();
        createDirTestClassFile();

        createMismatchJarV1();
        createMismatchJarV2();

        originalClasspath = System.getProperty("java.class.path");

        String newClasspath = originalClasspath
                + File.pathSeparator + testJarsDir.resolve("duplicate-v1.jar")
                + File.pathSeparator + testJarsDir.resolve("duplicate-v2.jar")
                + File.pathSeparator + testJarsDir.resolve("inner-v1.jar")
                + File.pathSeparator + testJarsDir.resolve("inner-v2.jar")
                + File.pathSeparator + testJarsDir.resolve("field-v1.jar")
                + File.pathSeparator + testJarsDir.resolve("field-v2.jar")
                + File.pathSeparator + testJarsDir.resolve("dirtest.jar")
                + File.pathSeparator + testDirClassesDir.toAbsolutePath()
                + File.pathSeparator + testJarsDir.resolve("mismatch-v1.jar")
                + File.pathSeparator + testJarsDir.resolve("mismatch-v2.jar");
        System.setProperty("java.class.path", newClasspath);
    }

    @org.junit.jupiter.api.AfterAll
    public static void tearDown() throws Exception {
        if (originalClasspath != null) {
            System.setProperty("java.class.path", originalClasspath);
        }
        cleanupDir(testJarsDir);
        cleanupDir(testDirClassesDir);
    }

    private static void cleanupDir(Path dir) {
        if (dir != null && Files.exists(dir)) {
            try {
                Files.walk(dir)
                    .sorted((a, b) -> b.compareTo(a))
                    .forEach(path -> {
                        try { Files.delete(path); } catch (IOException e) { /* ignore */ }
                    });
            } catch (IOException e) { /* ignore */ }
        }
    }

    // ===== Duplicate class detection =====

    @Test
    public void scanClasspath_findsDuplicateClasses() {
        LinkageHazardDetector detector = createDetector();

        detector.scanClasspath();

        assertFalse(detector.getDuplicateClasses().isEmpty());
        assertTrue(detector.getDuplicateClasses().containsKey("com.example.duplicate.DuplicateClass"));
    }

    @Test
    public void analyzeClass_methodMissingInOneJar_warnsAboutMissingMethod() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestCaller", generateCallerClass("methodB"));

        String warnings = output.toString();
        assertTrue(warnings.contains("[Shady] WARNING"), "Expected a warning to be emitted");
        assertTrue(warnings.contains("methodB"), "Expected warning about methodB");
    }

    @Test
    public void analyzeClass_methodPresentInAllJars_issuesNoWarning() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestCaller", generateCallerClass("methodA"));

        assertFalse(output.toString().contains("WARNING"),
                "Expected no warnings for method present in all JARs");
    }

    @Test
    public void analyzeClass_methodOnlyInSecondJar_warnsAboutFirstJar() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestCaller", generateCallerClass("methodC"));

        assertTrue(output.toString().contains("methodC"), "Expected warning about methodC");
    }

    // ===== Inner class scanning =====

    @Test
    public void analyzeClass_innerClassMethodMissing_warnsAboutInnerClass() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestInnerCaller", generateInnerClassCaller("innerMethodB"));

        String warnings = output.toString();
        assertTrue(warnings.contains("innerMethodB"), "Expected warning about innerMethodB");
        assertTrue(warnings.contains("Outer$Inner"), "Expected warning to mention Outer$Inner");
    }

    // ===== Field access detection =====

    @Test
    public void analyzeClass_fieldMissingInOneJar_warnsAboutMissingField() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestFieldCaller", generateFieldAccessCaller());

        String warnings = output.toString();
        assertTrue(warnings.contains("fieldX"), "Expected warning about fieldX");
        assertTrue(warnings.contains("Field access hazard"), "Expected Field access hazard message");
    }

    // ===== Directory classpath scanning =====

    @Test
    public void scanClasspath_directoryAndJarWithSameClass_detectsDuplicate() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestDirCaller", generateDirTestCaller("methodB"));

        String warnings = output.toString();
        assertTrue(warnings.contains("methodB"), "Expected warning about methodB");
        assertTrue(warnings.contains("DirClass"), "Expected warning to mention DirClass");
    }

    // ===== Static/instance mismatch =====

    @Test
    public void analyzeClass_staticInOneJarInstanceInAnother_warnsAboutMismatch() {
        LinkageHazardDetector detector = createDetector();
        detector.scanClasspath();
        output.reset();

        detector.analyzeClass("com/example/TestMismatchCaller", generateMismatchCaller());

        String warnings = output.toString();
        assertTrue(warnings.contains("Static/instance mismatch"), "Expected Static/instance mismatch message");
        assertTrue(warnings.contains("sharedMethod"), "Expected warning about sharedMethod");
    }

    // ===== Test JAR creation =====

    private static void createTestJarV1() throws IOException {
        writeJar("duplicate-v1.jar", "com/example/duplicate/DuplicateClass",
                generateClassWithMethods("com/example/duplicate/DuplicateClass",
                        new String[]{"methodA", "methodB"}));
    }

    private static void createTestJarV2() throws IOException {
        writeJar("duplicate-v2.jar", "com/example/duplicate/DuplicateClass",
                generateClassWithMethods("com/example/duplicate/DuplicateClass",
                        new String[]{"methodA", "methodC"}));
    }

    private static void createInnerClassJarV1() throws IOException {
        writeJar("inner-v1.jar", "com/example/inner/Outer$Inner",
                generateClassWithMethods("com/example/inner/Outer$Inner",
                        new String[]{"innerMethodA", "innerMethodB"}));
    }

    private static void createInnerClassJarV2() throws IOException {
        writeJar("inner-v2.jar", "com/example/inner/Outer$Inner",
                generateClassWithMethods("com/example/inner/Outer$Inner",
                        new String[]{"innerMethodA"}));
    }

    private static void createFieldJarV1() throws IOException {
        writeJar("field-v1.jar", "com/example/field/FieldClass",
                generateClassWithFields("com/example/field/FieldClass",
                        new String[]{"fieldX", "sharedField"}, null));
    }

    private static void createFieldJarV2() throws IOException {
        writeJar("field-v2.jar", "com/example/field/FieldClass",
                generateClassWithFields("com/example/field/FieldClass",
                        new String[]{"sharedField"}, null));
    }

    private static void createDirTestJar() throws IOException {
        writeJar("dirtest.jar", "com/example/dirtest/DirClass",
                generateClassWithMethods("com/example/dirtest/DirClass",
                        new String[]{"methodA", "methodB"}));
    }

    private static void createDirTestClassFile() throws IOException {
        Path classDir = testDirClassesDir.resolve("com/example/dirtest");
        Files.createDirectories(classDir);
        Files.write(classDir.resolve("DirClass.class"),
                generateClassWithMethods("com/example/dirtest/DirClass",
                        new String[]{"methodA"}));
    }

    private static void createMismatchJarV1() throws IOException {
        writeJar("mismatch-v1.jar", "com/example/mismatch/MismatchClass",
                generateClassWithStaticMethod("com/example/mismatch/MismatchClass",
                        "sharedMethod"));
    }

    private static void createMismatchJarV2() throws IOException {
        writeJar("mismatch-v2.jar", "com/example/mismatch/MismatchClass",
                generateClassWithMethods("com/example/mismatch/MismatchClass",
                        new String[]{"sharedMethod"}));
    }

    private static void writeJar(String jarName, String classPath, byte[] classBytes) throws IOException {
        Path jarPath = testJarsDir.resolve(jarName);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            jos.putNextEntry(new JarEntry(classPath + ".class"));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }

    // ===== Bytecode generation =====

    private static byte[] generateClassWithMethods(String className, String[] methodNames) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        for (String methodName : methodNames) {
            mv = cw.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
            mv.visitCode();
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateClassWithFields(String className, String[] fieldNames, String[] methodNames) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);

        for (String fieldName : fieldNames) {
            cw.visitField(Opcodes.ACC_PUBLIC, fieldName, "I", null, null).visitEnd();
        }

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        if (methodNames != null) {
            for (String methodName : methodNames) {
                mv = cw.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
                mv.visitCode();
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(0, 0);
                mv.visitEnd();
            }
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateClassWithStaticMethod(String className, String methodName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, methodName, "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateCallerClass(String methodName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestCaller", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "callMethod", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "com/example/duplicate/DuplicateClass");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "com/example/duplicate/DuplicateClass", "<init>", "()V", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "com/example/duplicate/DuplicateClass", methodName, "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateFieldAccessCaller() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestFieldCaller", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "accessField", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "com/example/field/FieldClass");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "com/example/field/FieldClass", "<init>", "()V", false);
        mv.visitFieldInsn(Opcodes.GETFIELD, "com/example/field/FieldClass", "fieldX", "I");
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateInnerClassCaller(String methodName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestInnerCaller", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "callInnerMethod", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "com/example/inner/Outer$Inner");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "com/example/inner/Outer$Inner", "<init>", "()V", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "com/example/inner/Outer$Inner", methodName, "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateDirTestCaller(String methodName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestDirCaller", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "callMethod", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "com/example/dirtest/DirClass");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "com/example/dirtest/DirClass", "<init>", "()V", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "com/example/dirtest/DirClass", methodName, "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] generateMismatchCaller() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestMismatchCaller", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "callMethod", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "com/example/mismatch/MismatchClass", "sharedMethod", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
