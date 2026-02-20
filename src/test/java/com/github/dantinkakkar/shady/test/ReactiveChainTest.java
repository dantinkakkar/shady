package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import org.junit.jupiter.api.AfterAll;
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
import java.util.Comparator;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for reactive call chains like MessageToMessageDecoder -> HttpContentDecompressor -> ZlibCodecFactory
 * This simulates real-world Netty reactive scenarios where calls go through multiple layers.
 */
public class ReactiveChainTest implements Opcodes {
    
    private static Path testJarsDir;
    private static String originalClasspath;
    
    @BeforeAll
    public static void setup() throws Exception {
        // Save original classpath
        originalClasspath = System.getProperty("java.class.path");
        
        // Create temporary directory for test JARs
        testJarsDir = Files.createTempDirectory("shady-reactive-test-");
        
        // Create two conflicting JARs simulating spring-boot vs netty
        createSpringBootJar();
        createNettyJar();
        
        // Add test JARs to classpath
        String testClasspath = originalClasspath + File.pathSeparator +
                              testJarsDir.resolve("spring-boot-sim.jar") + File.pathSeparator +
                              testJarsDir.resolve("netty-sim.jar");
        System.setProperty("java.class.path", testClasspath);
    }
    
    @AfterAll
    public static void tearDown() throws Exception {
        // Restore original classpath
        if (originalClasspath != null) {
            System.setProperty("java.class.path", originalClasspath);
        }
        
        // Clean up temporary test directory
        if (testJarsDir != null && Files.exists(testJarsDir)) {
            Files.walk(testJarsDir)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        // Ignore cleanup errors
                    }
                });
        }
    }
    
    /**
     * Create JAR with MessageToMessageDecoder -> HttpContentDecompressor -> ZlibCodecFactory chain
     * This version calls the spring-boot variant
     */
    private static void createSpringBootJar() throws IOException {
        Path jarPath = testJarsDir.resolve("spring-boot-sim.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Create MessageToMessageDecoder that calls HttpContentDecompressor
            byte[] decoderBytes = generateMessageToMessageDecoder();
            JarEntry entry = new JarEntry("io/netty/handler/codec/MessageToMessageDecoder.class");
            jos.putNextEntry(entry);
            jos.write(decoderBytes);
            jos.closeEntry();
            
            // Create HttpContentDecompressor that calls ZlibCodecFactory
            byte[] decompressorBytes = generateHttpContentDecompressor();
            entry = new JarEntry("io/netty/handler/codec/http/HttpContentDecompressor.class");
            jos.putNextEntry(entry);
            jos.write(decompressorBytes);
            jos.closeEntry();
            
            // Create ZlibCodecFactory with spring-boot variant method
            byte[] factoryBytes = generateZlibCodecFactory(true);
            entry = new JarEntry("io/netty/handler/codec/compression/ZlibCodecFactory.class");
            jos.putNextEntry(entry);
            jos.write(factoryBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Create JAR with conflicting ZlibCodecFactory (netty variant)
     */
    private static void createNettyJar() throws IOException {
        Path jarPath = testJarsDir.resolve("netty-sim.jar");
        
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            // Create ZlibCodecFactory with different method
            byte[] factoryBytes = generateZlibCodecFactory(false);
            JarEntry entry = new JarEntry("io/netty/handler/codec/compression/ZlibCodecFactory.class");
            jos.putNextEntry(entry);
            jos.write(factoryBytes);
            jos.closeEntry();
        }
    }
    
    /**
     * Generate MessageToMessageDecoder class
     */
    private static byte[] generateMessageToMessageDecoder() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V11, ACC_PUBLIC, "io/netty/handler/codec/MessageToMessageDecoder", null, "java/lang/Object", null);
        
        // Constructor
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        
        // decode() method that calls HttpContentDecompressor
        mv = cw.visitMethod(ACC_PUBLIC, "decode", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(NEW, "io/netty/handler/codec/http/HttpContentDecompressor");
        mv.visitInsn(DUP);
        mv.visitMethodInsn(INVOKESPECIAL, "io/netty/handler/codec/http/HttpContentDecompressor", "<init>", "()V", false);
        mv.visitMethodInsn(INVOKEVIRTUAL, "io/netty/handler/codec/http/HttpContentDecompressor", "decompress", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    /**
     * Generate HttpContentDecompressor class
     */
    private static byte[] generateHttpContentDecompressor() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V11, ACC_PUBLIC, "io/netty/handler/codec/http/HttpContentDecompressor", null, "java/lang/Object", null);
        
        // Constructor
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        
        // decompress() method that calls ZlibCodecFactory
        mv = cw.visitMethod(ACC_PUBLIC, "decompress", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(INVOKESTATIC, "io/netty/handler/codec/compression/ZlibCodecFactory", "newZlibDecoder", "()Ljava/lang/Object;", false);
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    /**
     * Generate ZlibCodecFactory with different methods depending on variant
     */
    private static byte[] generateZlibCodecFactory(boolean isSpringBoot) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(V11, ACC_PUBLIC, "io/netty/handler/codec/compression/ZlibCodecFactory", null, "java/lang/Object", null);
        
        // Constructor
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        
        if (isSpringBoot) {
            // Spring Boot variant: has newZlibDecoder() and springBootHelper()
            mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "newZlibDecoder", "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitMethodInsn(INVOKESTATIC, "io/netty/handler/codec/compression/ZlibCodecFactory", "springBootHelper", "()Ljava/lang/Object;", false);
            mv.visitInsn(ARETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
            
            mv = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "springBootHelper", "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
        } else {
            // Netty variant: has newZlibDecoder() and nettyHelper()
            mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "newZlibDecoder", "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitMethodInsn(INVOKESTATIC, "io/netty/handler/codec/compression/ZlibCodecFactory", "nettyHelper", "()Ljava/lang/Object;", false);
            mv.visitInsn(ARETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
            
            mv = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "nettyHelper", "()Ljava/lang/Object;", null, null);
            mv.visitCode();
            mv.visitInsn(ACONST_NULL);
            mv.visitInsn(ARETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
        }
        
        cw.visitEnd();
        return cw.toByteArray();
    }
    
    @Test
    public void testReactiveChainDetection() {
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Should detect the duplicate ZlibCodecFactory
        assertFalse(detector.getDuplicateClasses().isEmpty(), "Should detect duplicate classes");
        assertTrue(detector.getDuplicateClasses().containsKey("io.netty.handler.codec.compression.ZlibCodecFactory"),
                  "Should detect ZlibCodecFactory as duplicate");
        
        // Should detect hazards in the helper methods
        assertFalse(detector.getIssuedWarnings().isEmpty(), "Should detect linkage hazards");
        
        // Check that we detected the specific helper method conflicts
        boolean foundSpringBootHelper = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("springBootHelper"));
        boolean foundNettyHelper = detector.getIssuedWarnings().stream()
                .anyMatch(w -> w.contains("nettyHelper"));
        
        assertTrue(foundSpringBootHelper || foundNettyHelper, 
                  "Should detect at least one of the helper method hazards");
    }
    
    @Test
    public void testCallChainTracking() {
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // The detector should have built a call graph including the reactive chain
        // MessageToMessageDecoder.decode() -> HttpContentDecompressor.decompress() -> ZlibCodecFactory.newZlibDecoder()
        
        assertFalse(detector.getIssuedWarnings().isEmpty(), "Should have detected warnings in the call chain");
    }
}
