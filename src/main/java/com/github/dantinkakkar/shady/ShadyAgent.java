package com.github.dantinkakkar.shady;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class ShadyAgent {

    private static LinkageHazardDetector detector;

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[Shady] Java agent started - detecting linkage hazards...");

        try {
            AgentConfig config = new AgentConfig(agentArgs);
            HazardReporter reporter = new HazardReporter(config);

            JDKMethodRegistry jdkRegistry = null;
            if (config.isDetectJdkRemovals()) {
                long start = System.currentTimeMillis();
                jdkRegistry = JDKMethodRegistry.create();
                long elapsed = System.currentTimeMillis() - start;
                System.out.println("[Shady] JDK scan completed in " + elapsed + "ms (" + jdkRegistry.size() + " classes)");
            }

            detector = new LinkageHazardDetector(config, reporter, jdkRegistry);
            detector.scanClasspath();

            inst.addTransformer(new ShadyClassTransformer(detector, config), false);
            reporter.registerShutdownHook();

            System.out.println("[Shady] Agent initialized successfully");
        } catch (Exception e) {
            System.err.println("[Shady] Error initializing agent: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static class ShadyClassTransformer implements ClassFileTransformer {
        private final LinkageHazardDetector detector;
        private final AgentConfig config;

        public ShadyClassTransformer(LinkageHazardDetector detector, AgentConfig config) {
            this.detector = detector;
            this.config = config;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (className == null) return null;

            // Skip bootstrap classes and JDK/agent internals
            if (loader == null) return null;
            if (className.startsWith("java/") || className.startsWith("javax/")
                    || className.startsWith("sun/") || className.startsWith("jdk/")
                    || className.startsWith("com/github/dantinkakkar/shady/")) {
                return null;
            }

            // Apply user-specified include/exclude filters
            if (!config.shouldAnalyze(className)) return null;

            try {
                detector.analyzeClass(className, classfileBuffer);
            } catch (Exception e) {
                System.err.println("[Shady] Error analyzing class " + className + ": " + e.getMessage());
            }

            return null;
        }
    }

    public static LinkageHazardDetector getDetector() {
        return detector;
    }
}
