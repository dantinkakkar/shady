package com.github.dantinkakkar.shady.test;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Shady agent's linkage hazard detection.
 */
public class ShadyAgentTest {
    
    private static Path testJarsDir;
    private static String originalClasspath;
    
    @BeforeAll
    public static void setUp() throws Exception {
        // Create a temporary directory for test JARs
        testJarsDir = Files.createTempDirectory("shady-test-");
        
        // Create two JARs with the same class but different methods
        createTestJarV1();
        createTestJarV2();
        
        // Save original classpath
        originalClasspath = System.getProperty("java.class.path");
        
        // Add test JARs to classpath
        String newClasspath = originalClasspath + File.pathSeparator + 
                              testJarsDir.resolve("duplicate-v1.jar").toString() + File.pathSeparator +
                              testJarsDir.resolve("duplicate-v2.jar").toString();
        System.setProperty("java.class.path", newClasspath);
    }
    
    /**
     * Create version 1 JAR with methodA and methodB.
     */
    private static void createTestJarV1() throws IOException {
        Path jarPath = testJarsDir.resolve("duplicate-v1.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Add the duplicate class with methodA and methodB
            byte[] classBytes = generateClassWithMethods("com/example/duplicate/DuplicateClass", 
                                                          new String[]{"methodA", "methodB"});
            
            JarEntry entry = new JarEntry("com/example/duplicate/DuplicateClass.class");
            jos.putNextEntry(entry);
            jos.write(classBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Create version 2 JAR with methodA and methodC (missing methodB).
     */
    private static void createTestJarV2() throws IOException {
        Path jarPath = testJarsDir.resolve("duplicate-v2.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Add the duplicate class with methodA and methodC
            byte[] classBytes = generateClassWithMethods("com/example/duplicate/DuplicateClass", 
                                                          new String[]{"methodA", "methodC"});
            
            JarEntry entry = new JarEntry("com/example/duplicate/DuplicateClass.class");
            jos.putNextEntry(entry);
            jos.write(classBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Generate bytecode for a class with specified methods.
     */
    private static byte[] generateClassWithMethods(String className, String[] methodNames) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
        
        // Add default constructor
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        
        // Add specified methods
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
    
    /**
     * Generate bytecode that calls a method on DuplicateClass.
     */
    private static byte[] generateCallerClass(String methodName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestCaller", null, "java/lang/Object", null);
        
        // Add a method that calls the specified method
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
    
    @Test
    public void testDuplicateClassDetection() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Verify that duplicate class was detected
        assertFalse(detector.getDuplicateClasses().isEmpty(), 
                    "Should detect duplicate classes on classpath");
        
        assertTrue(detector.getDuplicateClasses().containsKey("com.example.duplicate.DuplicateClass"),
                   "Should detect DuplicateClass as duplicate");
    }
    
    @Test
    public void testLinkageHazardDetection() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Generate a class that calls methodB (which is missing in v2)
        byte[] callerBytes = generateCallerClass("methodB");
        
        // Analyze the caller class
        detector.analyzeClass("com/example/TestCaller", callerBytes);
        
        // Verify that a warning was issued for methodB
        assertFalse(detector.getIssuedWarnings().isEmpty(),
                    "Should issue warning for missing method");
        
        boolean foundMethodBWarning = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("methodB"));
        
        assertTrue(foundMethodBWarning,
                   "Should warn about methodB being missing in some versions");
    }
    
    @Test
    public void testNoWarningForMethodInAllVersions() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        int initialWarningCount = detector.getIssuedWarnings().size();
        
        // Generate a class that calls methodA (which exists in both versions)
        byte[] callerBytes = generateCallerClass("methodA");
        
        // Analyze the caller class
        detector.analyzeClass("com/example/TestCaller", callerBytes);
        
        // Count new warnings
        int newWarningCount = detector.getIssuedWarnings().size();
        
        // Should not issue warning for methodA since it exists in all versions
        assertEquals(initialWarningCount, newWarningCount,
                     "Should not warn about methodA since it exists in all versions");
    }
    
    @Test
    public void testMethodCHazardDetection() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Generate a class that calls methodC (which is missing in v1)
        byte[] callerBytes = generateCallerClass("methodC");
        
        // Analyze the caller class
        detector.analyzeClass("com/example/TestCaller", callerBytes);
        
        // Verify that a warning was issued for methodC
        boolean foundMethodCWarning = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("methodC"));
        
        assertTrue(foundMethodCWarning,
                   "Should warn about methodC being missing in some versions");
    }
}
