package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Golden test case for the ZlibCodecFactory linkage issue with
 * spring-boot-starter-webflux and netty-codec-http dependencies.
 * 
 * This test simulates the real-world scenario where:
 * - spring-boot-starter-webflux:3.4.4 includes a version of ZlibCodecFactory
 * - io.netty:netty-codec-http:4.1.125.Final includes a different version
 * - The method signatures match, but internal calls differ
 * - This causes a NoSuchMethodError in production when the wrong version is loaded
 */
public class ZlibCodecFactoryTest {
    
    private static Path testJarsDir;
    private static String originalClasspath;
    
    @BeforeAll
    public static void setUp() throws Exception {
        // Create a temporary directory for test JARs
        testJarsDir = Files.createTempDirectory("shady-zlib-test-");
        
        // Create two JARs simulating the spring-boot and netty scenario
        createSpringBootWebfluxJar();
        createNettyCodecHttpJar();
        
        // Save original classpath
        originalClasspath = System.getProperty("java.class.path");
        
        // Add test JARs to classpath
        String newClasspath = originalClasspath + File.pathSeparator + 
                              testJarsDir.resolve("spring-boot-webflux-sim.jar").toString() + File.pathSeparator +
                              testJarsDir.resolve("netty-codec-http-sim.jar").toString();
        System.setProperty("java.class.path", newClasspath);
    }
    
    @org.junit.jupiter.api.AfterAll
    public static void tearDown() throws Exception {
        // Restore original classpath
        if (originalClasspath != null) {
            System.setProperty("java.class.path", originalClasspath);
        }
        
        // Clean up temporary test directory
        if (testJarsDir != null && Files.exists(testJarsDir)) {
            Files.walk(testJarsDir)
                .sorted((a, b) -> b.compareTo(a)) // Delete files before directories
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        System.err.println("Failed to delete: " + path);
                    }
                });
        }
    }
    
    /**
     * Create a JAR simulating spring-boot-starter-webflux's version of ZlibCodecFactory.
     * This version has newZlibEncoder() which calls an internal method that exists in this version.
     */
    private static void createSpringBootWebfluxJar() throws IOException {
        Path jarPath = testJarsDir.resolve("spring-boot-webflux-sim.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Add ZlibCodecFactory with newZlibEncoder() that calls newZlibEncoderInternal()
            byte[] zlibFactoryBytes = generateZlibCodecFactory(true);
            JarEntry entry = new JarEntry("io/netty/handler/codec/compression/ZlibCodecFactory.class");
            jos.putNextEntry(entry);
            jos.write(zlibFactoryBytes);
            jos.closeEntry();
            
            // Add the internal helper class that exists in spring-boot's version
            byte[] helperBytes = generateZlibEncoderHelper(true);
            entry = new JarEntry("io/netty/handler/codec/compression/ZlibEncoderHelper.class");
            jos.putNextEntry(entry);
            jos.write(helperBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Create a JAR simulating netty-codec-http's version of ZlibCodecFactory.
     * This version has the same newZlibEncoder() method but it calls a different internal method
     * that doesn't exist in the spring-boot version.
     */
    private static void createNettyCodecHttpJar() throws IOException {
        Path jarPath = testJarsDir.resolve("netty-codec-http-sim.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Add ZlibCodecFactory with newZlibEncoder() that calls createZlibEncoder()
            byte[] zlibFactoryBytes = generateZlibCodecFactory(false);
            JarEntry entry = new JarEntry("io/netty/handler/codec/compression/ZlibCodecFactory.class");
            jos.putNextEntry(entry);
            jos.write(zlibFactoryBytes);
            jos.closeEntry();
            
            // Add the internal helper class with a DIFFERENT method that only exists in netty's version
            byte[] helperBytes = generateZlibEncoderHelper(false);
            entry = new JarEntry("io/netty/handler/codec/compression/ZlibEncoderHelper.class");
            jos.putNextEntry(entry);
            jos.write(helperBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Generate bytecode for ZlibCodecFactory.
     * Both versions have the same public API (newZlibEncoder), but they call different internal methods.
     */
    private static byte[] generateZlibCodecFactory(boolean isSpringBootVersion) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, 
                 "io/netty/handler/codec/compression/ZlibCodecFactory", 
                 null, "java/lang/Object", null);
        
        // Add default constructor
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        
        // Add the public newZlibEncoder() method
        // The method signature is the same in both versions, but internal calls differ
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, 
                           "newZlibEncoder", 
                           "()Ljava/lang/Object;", 
                           null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "io/netty/handler/codec/compression/ZlibEncoderHelper");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, 
                          "io/netty/handler/codec/compression/ZlibEncoderHelper", 
                          "<init>", "()V", false);
        
        // Call different methods depending on version
        if (isSpringBootVersion) {
            // Spring Boot version calls newZlibEncoderInternal()
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, 
                              "io/netty/handler/codec/compression/ZlibEncoderHelper", 
                              "newZlibEncoderInternal", "()Ljava/lang/Object;", false);
        } else {
            // Netty version calls createZlibEncoder()
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, 
                              "io/netty/handler/codec/compression/ZlibEncoderHelper", 
                              "createZlibEncoder", "()Ljava/lang/Object;", false);
        }
        
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    /**
     * Generate bytecode for ZlibEncoderHelper.
     * Each version has different methods available.
     */
    private static byte[] generateZlibEncoderHelper(boolean isSpringBootVersion) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, 
                 "io/netty/handler/codec/compression/ZlibEncoderHelper", 
                 null, "java/lang/Object", null);
        
        // Add default constructor
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        
        if (isSpringBootVersion) {
            // Spring Boot version has newZlibEncoderInternal()
            mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "newZlibEncoderInternal", 
                               "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitInsn(Opcodes.ACONST_NULL);
            mv.visitInsn(Opcodes.ARETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        } else {
            // Netty version has createZlibEncoder()
            mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "createZlibEncoder", 
                               "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitInsn(Opcodes.ACONST_NULL);
            mv.visitInsn(Opcodes.ARETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    /**
     * Generate bytecode for a caller that invokes ZlibCodecFactory.newZlibEncoder().
     */
    private static byte[] generateCallerClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/WebFluxApp", 
                null, "java/lang/Object", null);
        
        // Add a method that calls ZlibCodecFactory.newZlibEncoder()
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "startServer", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                          "io/netty/handler/codec/compression/ZlibCodecFactory", 
                          "newZlibEncoder", 
                          "()Ljava/lang/Object;", 
                          false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    @Test
    public void testZlibCodecFactoryDuplicateDetection() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Verify that ZlibCodecFactory was detected as duplicate
        assertTrue(detector.getDuplicateClasses().containsKey(
                "io.netty.handler.codec.compression.ZlibCodecFactory"),
                "Should detect ZlibCodecFactory as duplicate");
        
        // Verify that ZlibEncoderHelper was detected as duplicate
        assertTrue(detector.getDuplicateClasses().containsKey(
                "io.netty.handler.codec.compression.ZlibEncoderHelper"),
                "Should detect ZlibEncoderHelper as duplicate");
    }
    
    @Test
    public void testZlibCodecFactoryTransitiveHazardDetection() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Generate a caller that invokes ZlibCodecFactory.newZlibEncoder()
        byte[] callerBytes = generateCallerClass();
        
        // Analyze the caller class
        detector.analyzeClass("com/example/WebFluxApp", callerBytes);
        
        // The key test: Should detect that the transitive call from newZlibEncoder() 
        // to either newZlibEncoderInternal() or createZlibEncoder() will fail
        // because these methods don't exist in all versions
        assertFalse(detector.getIssuedWarnings().isEmpty(),
                    "Should issue warning for transitive linkage hazard");
        
        // Verify we detected issues with the ZlibEncoderHelper methods
        boolean foundTransitiveHazard = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("ZlibEncoderHelper") && 
                             (w.contains("newZlibEncoderInternal") || w.contains("createZlibEncoder")));
        
        assertTrue(foundTransitiveHazard,
                   "Should detect transitive hazard in ZlibEncoderHelper methods called by ZlibCodecFactory");
    }
    
    @Test
    public void testNoDirectHazardOnZlibCodecFactoryPublicAPI() {
        // Create and initialize detector
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Generate a caller that invokes ZlibCodecFactory.newZlibEncoder()
        byte[] callerBytes = generateCallerClass();
        
        // Analyze the caller class
        detector.analyzeClass("com/example/WebFluxApp", callerBytes);
        
        // The public API method newZlibEncoder() exists in both versions
        // So there should NOT be a direct hazard warning for it
        boolean hasDirectHazardOnPublicAPI = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("ZlibCodecFactory.newZlibEncoder"));
        
        assertFalse(hasDirectHazardOnPublicAPI,
                   "Should NOT warn about public API method that exists in all versions");
    }
}
