package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import com.github.dantinkakkar.shady.LinkageHazardDetector.LinkageHazard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ShadyAgentTest {

    private static final String TARGET = "com.example.Target";
    private static final String MISSING_METHOD = "newApi(I)V";
    private static final String CALLER = "com.example.Caller.run()V";

    @TempDir
    Path tempDir;

    @Test
    void detectsMissingMethodOnEffectiveDefinitionWithoutDuplicates() throws IOException {
        Path callerJar = writeJar("caller.jar", Map.of(
                "com/example/Caller.class", callerCallingStaticMethod(
                        "com/example/Target", "newApi", "(I)V")));
        Path targetJar = writeJar("target-old.jar", Map.of(
                "com/example/Target.class", targetWithoutNewApi("com/example/Target")));

        LinkageHazardDetector detector = scan(callerJar, targetJar);

        assertFalse(detector.getDuplicateClasses().containsKey(TARGET),
                "The real failure does not require a duplicate class");
        LinkageHazard hazard = findHazard(detector, TARGET, MISSING_METHOD, CALLER);
        assertEquals(targetJar.toAbsolutePath().normalize().toString(), hazard.getTargetLocation());
    }

    @Test
    void doesNotWarnWhenEffectiveDefinitionContainsMethod() throws IOException {
        Path callerJar = writeJar("caller.jar", Map.of(
                "com/example/Caller.class", callerCallingStaticMethod(
                        "com/example/Target", "newApi", "(I)V")));
        Path targetJar = writeJar("target-new.jar", Map.of(
                "com/example/Target.class", targetWithNewApi("com/example/Target")));

        LinkageHazardDetector detector = scan(callerJar, targetJar);

        assertFalse(hasHazard(detector, TARGET, MISSING_METHOD, CALLER));
    }

    @Test
    void resolvesMethodsInheritedFromAnIndexedSuperclass() throws IOException {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("com/example/Base.class", baseWithPing());
        classes.put("com/example/Child.class", childOfBase());
        classes.put("com/example/Caller.class", callerCallingInheritedMethod());

        LinkageHazardDetector detector = scan(writeJar("inheritance.jar", classes));

        assertFalse(hasHazard(
                detector,
                "com.example.Child",
                "ping()V",
                "com.example.Caller.run()V"));
    }

    @Test
    void indexesInnerClassesInsteadOfSilentlySkippingThem() throws IOException {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("com/example/Outer$Inner.class", targetWithNewApi("com/example/Outer$Inner"));
        classes.put("com/example/Caller.class", callerCallingStaticMethod(
                "com/example/Outer$Inner", "newApi", "(I)V"));

        LinkageHazardDetector detector = scan(writeJar("inner-class.jar", classes));

        assertFalse(hasHazard(
                detector,
                "com.example.Outer$Inner",
                MISSING_METHOD,
                CALLER));
    }

    @Test
    void scansLibrariesNestedInsideASpringBootExecutableJar() throws IOException {
        byte[] callerJar = jarBytes(Map.of(
                "com/example/Caller.class", callerCallingStaticMethod(
                        "com/example/Target", "newApi", "(I)V")));
        byte[] targetJar = jarBytes(Map.of(
                "com/example/Target.class", targetWithoutNewApi("com/example/Target")));

        Map<String, byte[]> bootEntries = new LinkedHashMap<>();
        bootEntries.put("BOOT-INF/lib/caller.jar", callerJar);
        bootEntries.put("BOOT-INF/lib/netty-codec-4.1.119.Final.jar", targetJar);
        Path bootJar = writeJar("application.jar", bootEntries);

        LinkageHazardDetector detector = scan(bootJar);

        LinkageHazard hazard = findHazard(detector, TARGET, MISSING_METHOD, CALLER);
        assertTrue(hazard.getTargetLocation().endsWith(
                "application.jar!/BOOT-INF/lib/netty-codec-4.1.119.Final.jar"));
    }

    @Test
    void preservesDuplicateReportingWhileUsingTheFirstDefinitionAsEffective() throws IOException {
        Path callerJar = writeJar("caller.jar", Map.of(
                "com/example/Caller.class", callerCallingStaticMethod(
                        "com/example/Target", "newApi", "(I)V")));
        Path oldTarget = writeJar("target-old.jar", Map.of(
                "com/example/Target.class", targetWithoutNewApi("com/example/Target")));
        Path newTarget = writeJar("target-new.jar", Map.of(
                "com/example/Target.class", targetWithNewApi("com/example/Target")));

        LinkageHazardDetector detector = scan(callerJar, oldTarget, newTarget);

        assertEquals(2, detector.getDuplicateClasses().get(TARGET).size());
        LinkageHazard hazard = findHazard(detector, TARGET, MISSING_METHOD, CALLER);
        assertEquals(oldTarget.toAbsolutePath().normalize().toString(), hazard.getTargetLocation());
    }

    private LinkageHazardDetector scan(Path... entries) {
        StringBuilder classpath = new StringBuilder();
        for (Path entry : entries) {
            if (classpath.length() > 0) {
                classpath.append(File.pathSeparator);
            }
            classpath.append(entry.toAbsolutePath().normalize());
        }

        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath(classpath.toString());
        return detector;
    }

    private LinkageHazard findHazard(LinkageHazardDetector detector, String target,
                                     String method, String caller) {
        return detector.getDetectedHazards().stream()
                .filter(hazard -> target.equals(hazard.getTargetClassName()))
                .filter(hazard -> method.equals(hazard.getMethodSignature()))
                .filter(hazard -> caller.equals(hazard.getCallerSignature()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Expected exact linkage hazard " + caller + " -> " + target + "." + method
                                + ", got " + detector.getDetectedHazards()));
    }

    private boolean hasHazard(LinkageHazardDetector detector, String target,
                              String method, String caller) {
        return detector.getDetectedHazards().stream()
                .anyMatch(hazard -> target.equals(hazard.getTargetClassName())
                        && method.equals(hazard.getMethodSignature())
                        && caller.equals(hazard.getCallerSignature()));
    }

    private Path writeJar(String fileName, Map<String, byte[]> entries) throws IOException {
        Path jar = tempDir.resolve(fileName);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            writeEntries(output, entries);
        }
        return jar;
    }

    private static byte[] jarBytes(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (JarOutputStream output = new JarOutputStream(bytes)) {
            writeEntries(output, entries);
        }
        return bytes.toByteArray();
    }

    private static void writeEntries(JarOutputStream output, Map<String, byte[]> entries)
            throws IOException {
        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            JarEntry jarEntry = new JarEntry(entry.getKey());
            jarEntry.setTime(0L);
            output.putNextEntry(jarEntry);
            output.write(entry.getValue());
            output.closeEntry();
        }
    }

    private static byte[] targetWithoutNewApi(String internalName) {
        return classWithStaticMethod(internalName, "oldApi", "()V");
    }

    private static byte[] targetWithNewApi(String internalName) {
        return classWithStaticMethod(internalName, "newApi", "(I)V");
    }

    private static byte[] classWithStaticMethod(String internalName, String name,
                                                String descriptor) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        addConstructor(writer, "java/lang/Object");

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, descriptor, null, null);
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] callerCallingStaticMethod(String owner, String methodName,
                                                    String descriptor) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/Caller", null,
                "java/lang/Object", null);
        addConstructor(writer, "java/lang/Object");

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, owner, methodName, descriptor, false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] baseWithPing() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/Base", null,
                "java/lang/Object", null);
        addConstructor(writer, "java/lang/Object");
        MethodVisitor ping = writer.visitMethod(Opcodes.ACC_PUBLIC, "ping", "()V", null, null);
        ping.visitCode();
        ping.visitInsn(Opcodes.RETURN);
        ping.visitMaxs(0, 0);
        ping.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] childOfBase() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/Child", null,
                "com/example/Base", null);
        addConstructor(writer, "com/example/Base");
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] callerCallingInheritedMethod() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/Caller", null,
                "java/lang/Object", null);
        addConstructor(writer, "java/lang/Object");

        MethodVisitor method = writer.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, "com/example/Child");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(
                Opcodes.INVOKESPECIAL, "com/example/Child", "<init>", "()V", false);
        method.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL, "com/example/Child", "ping", "()V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void addConstructor(ClassWriter writer, String superName) {
        MethodVisitor constructor = writer.visitMethod(
                Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(
                Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
    }
}
