package com.github.dantinkakkar.shady;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Java agent that detects latent JVM linkage hazards from duplicate classes on the classpath.
 * Scans loaded bytecode for method calls and warns if those methods are missing in alternative
 * runtime definitions of the same class.
 */
public class ShadyAgent {
    
    private static LinkageHazardDetector detector;
    
    /**
     * Premain method called when agent is loaded at JVM startup.
     *
     * @param agentArgs command-line arguments for the agent
     * @param inst instrumentation interface
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[Shady] Java agent started - detecting linkage hazards...");
        
        try {
            // Initialize the detector
            detector = new LinkageHazardDetector();
            
            // Scan the classpath for duplicate classes
            detector.scanClasspath();
            
            // Register transformer to scan loaded classes
            inst.addTransformer(new ShadyClassTransformer(detector), false);
            
            System.out.println("[Shady] Agent initialized successfully");
        } catch (Exception e) {
            System.err.println("[Shady] Error initializing agent: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * ClassFileTransformer that analyzes bytecode for potential linkage hazards.
     */
    private static class ShadyClassTransformer implements ClassFileTransformer {
        private final LinkageHazardDetector detector;
        
        public ShadyClassTransformer(LinkageHazardDetector detector) {
            this.detector = detector;
        }
        
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            try {
                // Analyze the class for linkage hazards
                detector.analyzeClass(className, classfileBuffer);
            } catch (Exception e) {
                // Don't crash - just log the error
                System.err.println("[Shady] Error analyzing class " + className + ": " + e.getMessage());
            }
            
            // Return null to indicate no transformation
            return null;
        }
    }
    
    /**
     * Get the detector instance (for testing purposes).
     */
    public static LinkageHazardDetector getDetector() {
        return detector;
    }
}
