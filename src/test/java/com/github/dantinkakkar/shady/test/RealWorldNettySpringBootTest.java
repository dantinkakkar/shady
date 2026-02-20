package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test using REAL Spring Boot and Netty JARs to detect actual linkage hazards.
 * 
 * This test manually downloads and adds both conflicting versions of netty-codec to the classpath
 * to validate detection of the known issue where:
 * - spring-boot-starter-webflux:3.4.4 brings netty-codec:4.1.119.Final  
 * - netty-codec-http:4.1.125.Final brings netty-codec:4.1.125.Final
 * - HttpContentDecompressor calls ZlibCodecFactory.newContentDecoder()
 * - Different versions have incompatible method signatures/implementations
 */
public class RealWorldNettySpringBootTest {
    
    private static String originalClasspath;
    private static Path nettyCodec119Jar;
    private static Path nettyCodec125Jar;
    private static Path nettyCodecHttp119Jar;
    private static Path nettyCodecHttp125Jar;
    
    @BeforeAll
    public static void setup() throws Exception {
        originalClasspath = System.getProperty("java.class.path");
        
        // Download netty-codec 4.1.119.Final (from Spring Boot)
        nettyCodec119Jar = downloadJarFromMaven(
            "io.netty", "netty-codec", "4.1.119.Final"
        );
        
        // Download netty-codec 4.1.125.Final  
        nettyCodec125Jar = downloadJarFromMaven(
            "io.netty", "netty-codec", "4.1.125.Final"
        );
        
        // Download netty-codec-http 4.1.119.Final (contains HttpContentDecompressor)
        nettyCodecHttp119Jar = downloadJarFromMaven(
            "io.netty", "netty-codec-http", "4.1.119.Final"
        );
        
        // Download netty-codec-http 4.1.125.Final
        nettyCodecHttp125Jar = downloadJarFromMaven(
            "io.netty", "netty-codec-http", "4.1.125.Final"
        );
        
        // Add both JARs to classpath
        String newClasspath = originalClasspath + File.pathSeparator +
                             nettyCodec119Jar + File.pathSeparator +
                             nettyCodec125Jar + File.pathSeparator +
                             nettyCodecHttp119Jar + File.pathSeparator +
                             nettyCodecHttp125Jar;
        System.setProperty("java.class.path", newClasspath);
    }
    
    @AfterAll
    public static void tearDown() {
        if (originalClasspath != null) {
            System.setProperty("java.class.path", originalClasspath);
        }
    }
    
    private static Path downloadJarFromMaven(String groupId, String artifactId, String version) throws Exception {
        // Check if already in local Maven repo
        String groupPath = groupId.replace('.', '/');
        Path localRepo = Path.of(System.getProperty("user.home"), ".m2", "repository");
        Path jarPath = localRepo.resolve(groupPath).resolve(artifactId).resolve(version)
                                .resolve(artifactId + "-" + version + ".jar");
        
        if (Files.exists(jarPath)) {
            System.out.println("[Test] Using existing JAR: " + jarPath);
            return jarPath;
        }
        
        // Download from Maven Central
        String mavenUrl = String.format(
            "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
            groupPath, artifactId, version, artifactId, version
        );
        
        System.out.println("[Test] Downloading: " + mavenUrl);
        Files.createDirectories(jarPath.getParent());
        
        try (var in = new URL(mavenUrl).openStream()) {
            Files.copy(in, jarPath, StandardCopyOption.REPLACE_EXISTING);
        }
        
        System.out.println("[Test] Downloaded to: " + jarPath);
        return jarPath;
    }
    
    @Test
    public void testDetectsZlibCodecFactoryDuplicate() {
        // Create detector and scan the classpath which now includes both netty-codec versions
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Print duplicate classes for debugging
        System.out.println("[Test] Duplicate classes found: " + detector.getDuplicateClasses().size());
        for (String className : detector.getDuplicateClasses().keySet()) {
            System.out.println("  - " + className);
        }
        
        // Verify ZlibCodecFactory is detected as a duplicate
        assertTrue(detector.getDuplicateClasses().containsKey("io.netty.handler.codec.compression.ZlibCodecFactory"),
                  "Should detect ZlibCodecFactory as duplicate class");
    }
    
    @Test
    public void testDetectsLinkageHazards() {
        // Create detector and scan
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Should have detected linkage hazards
        assertFalse(detector.getIssuedWarnings().isEmpty(), 
                   "Should detect linkage hazards with conflicting netty-codec versions");
        
        // Print warnings for analysis
        System.out.println("[Test] Warnings detected: " + detector.getIssuedWarnings().size());
        for (String warning : detector.getIssuedWarnings()) {
            System.out.println("Warning: " + warning);
        }
    }
    
    @Test
    public void testDetectsHttpContentDecompressorToZlibCodecFactoryChain() {
        // Create detector and scan
        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath();
        
        // Look for warnings involving the call chain from HttpContentDecompressor to ZlibCodecFactory
        boolean foundRelevantHazard = false;
        
        for (String warning : detector.getIssuedWarnings()) {
            // Check if warning involves HttpContentDecompressor or ZlibCodecFactory
            if ((warning.contains("HttpContentDecompressor") || warning.contains("ZlibCodecFactory")) &&
                (warning.contains("Decoder") || warning.contains("decoder") || warning.contains("Zlib"))) {
                foundRelevantHazard = true;
                System.out.println("[Test] Found relevant hazard: " + warning);
            }
        }
        
        // If not found, print all warnings for debugging
        if (!foundRelevantHazard) {
            System.out.println("[Test] Did not find HttpContentDecompressor->ZlibCodecFactory hazard.");
            System.out.println("[Test] All warnings (" + detector.getIssuedWarnings().size() + "):");
            for (String warning : detector.getIssuedWarnings()) {
                System.out.println("  - " + warning);
            }
        }
        
        assertTrue(foundRelevantHazard,
                  "Should detect linkage hazard in HttpContentDecompressor calling ZlibCodecFactory methods");
    }
}
