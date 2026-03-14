package com.github.dantinkakkar.shady;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;

public class LinkageHazardDetector {

    private final Map<String, List<ClassLocation>> duplicateClasses = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Set<String>>> classMethodSets = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Set<String>>> classFieldSets = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Map<String, Integer>>> classMethodAccessFlags = new ConcurrentHashMap<>();

    private final AgentConfig config;
    private final HazardReporter reporter;
    private final JDKMethodRegistry jdkRegistry;

    private static class ClassLocation {
        final String jarPath;
        final String className;

        ClassLocation(String jarPath, String className) {
            this.jarPath = jarPath;
            this.className = className;
        }

        @Override
        public String toString() {
            return jarPath + "!" + className;
        }
    }

    public LinkageHazardDetector() {
        this(new AgentConfig(null), new HazardReporter(new AgentConfig(null)), null);
    }

    public LinkageHazardDetector(AgentConfig config, HazardReporter reporter, JDKMethodRegistry jdkRegistry) {
        this.config = config;
        this.reporter = reporter;
        this.jdkRegistry = jdkRegistry;
    }

    public void scanClasspath() {
        System.out.println("[Shady] Scanning classpath for duplicate classes...");

        String classpath = System.getProperty("java.class.path");
        String[] classpathEntries = classpath.split(File.pathSeparator);

        Map<String, List<String>> classLocations = new HashMap<>();

        for (String entry : classpathEntries) {
            File file = new File(entry);
            if (file.exists()) {
                if (file.isDirectory()) {
                    scanDirectory(file, classLocations);
                } else if (file.getName().endsWith(".jar")) {
                    scanJar(file, classLocations);
                }
            }
        }

        for (Map.Entry<String, List<String>> entry : classLocations.entrySet()) {
            String className = entry.getKey();
            List<String> locations = entry.getValue();

            if (locations.size() > 1) {
                List<ClassLocation> classLocs = new ArrayList<>();
                for (String loc : locations) {
                    classLocs.add(new ClassLocation(loc, className));
                }
                duplicateClasses.put(className, classLocs);
                analyzeMethodsInDuplicates(className, locations);
            }
        }

        if (!duplicateClasses.isEmpty()) {
            System.out.println("[Shady] Found " + duplicateClasses.size() + " duplicate classes on classpath");
        } else {
            System.out.println("[Shady] No duplicate classes found on classpath");
        }
    }

    private void scanJar(File jarFile, Map<String, List<String>> classLocations) {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (name.endsWith(".class")) {
                    String className = name.replace("/", ".").substring(0, name.length() - 6);
                    classLocations.computeIfAbsent(className, k -> new ArrayList<>())
                            .add(jarFile.getAbsolutePath());
                }
            }
        } catch (IOException e) {
            System.err.println("[Shady] Error scanning JAR " + jarFile + ": " + e.getMessage());
        }
    }

    private void scanDirectory(File dir, Map<String, List<String>> classLocations) {
        try (Stream<Path> paths = Files.walk(dir.toPath())) {
            paths.filter(p -> p.toString().endsWith(".class"))
                 .forEach(p -> {
                     String relative = dir.toPath().relativize(p).toString();
                     String className = relative.replace(File.separatorChar, '.')
                                                .replace('/', '.');
                     className = className.substring(0, className.length() - 6);
                     classLocations.computeIfAbsent(className, k -> new ArrayList<>())
                             .add(dir.getAbsolutePath());
                 });
        } catch (IOException e) {
            System.err.println("[Shady] Error scanning directory " + dir + ": " + e.getMessage());
        }
    }

    private void analyzeMethodsInDuplicates(String className, List<String> locations) {
        Map<String, Set<String>> methodsByLocation = new HashMap<>();

        for (String location : locations) {
            Set<String> methods = extractPublicProtectedMethods(location, className);
            if (methods != null) {
                methodsByLocation.put(location, methods);
            }
        }

        if (!methodsByLocation.isEmpty()) {
            classMethodSets.put(className, methodsByLocation);
        }
    }

    private byte[] readClassBytesFromLocation(String location, String className) {
        File file = new File(location);
        String entryName = className.replace(".", "/") + ".class";

        if (file.isDirectory()) {
            try {
                Path classPath = file.toPath().resolve(entryName);
                if (Files.exists(classPath)) {
                    return Files.readAllBytes(classPath);
                }
            } catch (IOException e) {
                System.err.println("[Shady] Error reading class " + className + " from " + location);
            }
        } else {
            try (JarFile jar = new JarFile(location)) {
                JarEntry entry = jar.getJarEntry(entryName);
                if (entry != null) {
                    try (InputStream is = jar.getInputStream(entry)) {
                        return is.readAllBytes();
                    }
                }
            } catch (IOException e) {
                System.err.println("[Shady] Error reading class " + className + " from " + location);
            }
        }
        return null;
    }

    private Set<String> extractPublicProtectedMethods(String location, String className) {
        Set<String> methods = new HashSet<>();
        Set<String> fields = new HashSet<>();
        Map<String, Integer> methodFlags = new HashMap<>();

        byte[] classBytes = readClassBytesFromLocation(location, className);
        if (classBytes == null) return methods;

        try {
            ClassReader reader = new ClassReader(classBytes);
            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    boolean isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
                    boolean isProtected = (access & Opcodes.ACC_PROTECTED) != 0;
                    if (isPublic || isProtected) {
                        String sig = name + descriptor;
                        methods.add(sig);
                        methodFlags.put(sig, access);
                    }
                    return null;
                }

                @Override
                public FieldVisitor visitField(int access, String name, String descriptor,
                                                String signature, Object value) {
                    boolean isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
                    boolean isProtected = (access & Opcodes.ACC_PROTECTED) != 0;
                    if (isPublic || isProtected) {
                        fields.add(name + ":" + descriptor);
                    }
                    return null;
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (Exception e) {
            System.err.println("[Shady] Error parsing class " + className + " from " + location);
        }

        classFieldSets.computeIfAbsent(className, k -> new ConcurrentHashMap<>()).put(location, fields);
        classMethodAccessFlags.computeIfAbsent(className, k -> new ConcurrentHashMap<>()).put(location, methodFlags);

        return methods;
    }

    public void analyzeClass(String className, byte[] classfileBuffer) {
        if (className == null || classfileBuffer == null) {
            return;
        }

        try {
            ClassReader reader = new ClassReader(classfileBuffer);

            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String name,
                                                     String descriptor, boolean isInterface) {
                            checkMethodCall(owner.replace("/", "."), name + descriptor);
                            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                        }

                        @Override
                        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                            checkFieldAccess(owner.replace("/", "."), name + ":" + descriptor);
                            super.visitFieldInsn(opcode, owner, name, descriptor);
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        } catch (Exception e) {
            System.err.println("[Shady] Error analyzing class " + className + ": " + e.getMessage());
        }
    }

    private void checkMethodCall(String targetClassName, String methodSignature) {
        Map<String, Set<String>> methodsByLocation = classMethodSets.get(targetClassName);

        if (methodsByLocation != null && methodsByLocation.size() > 1) {
            boolean missingInSome = false;
            List<String> missingLocations = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : methodsByLocation.entrySet()) {
                if (!entry.getValue().contains(methodSignature)) {
                    missingInSome = true;
                    missingLocations.add(entry.getKey());
                }
            }

            if (missingInSome) {
                reporter.report(new Hazard(
                        Hazard.Type.MISSING_METHOD,
                        Hazard.Severity.WARNING,
                        targetClassName,
                        methodSignature,
                        missingLocations
                ));
            } else {
                checkStaticInstanceMismatch(targetClassName, methodSignature);
            }
        }

        if (jdkRegistry != null && jdkRegistry.isJdkClass(targetClassName)
                && !jdkRegistry.hasMethod(targetClassName, methodSignature)) {
            reporter.report(new Hazard(
                    Hazard.Type.JDK_REMOVED_METHOD,
                    Hazard.Severity.ERROR,
                    targetClassName,
                    methodSignature,
                    Collections.singletonList("JDK runtime")
            ));
        }
    }

    private void checkFieldAccess(String targetClassName, String fieldSignature) {
        Map<String, Set<String>> fieldsByLocation = classFieldSets.get(targetClassName);
        if (fieldsByLocation != null && fieldsByLocation.size() > 1) {
            boolean missingInSome = false;
            List<String> missingLocations = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : fieldsByLocation.entrySet()) {
                if (!entry.getValue().contains(fieldSignature)) {
                    missingInSome = true;
                    missingLocations.add(entry.getKey());
                }
            }

            if (missingInSome) {
                reporter.report(new Hazard(
                        Hazard.Type.MISSING_FIELD,
                        Hazard.Severity.WARNING,
                        targetClassName,
                        fieldSignature,
                        missingLocations
                ));
            }
        }
    }

    private void checkStaticInstanceMismatch(String targetClassName, String methodSignature) {
        Map<String, Map<String, Integer>> accessByLocation = classMethodAccessFlags.get(targetClassName);
        if (accessByLocation == null || accessByLocation.size() < 2) return;

        boolean hasStatic = false;
        boolean hasInstance = false;
        List<String> allLocations = new ArrayList<>();

        for (Map.Entry<String, Map<String, Integer>> locEntry : accessByLocation.entrySet()) {
            Integer flags = locEntry.getValue().get(methodSignature);
            if (flags != null) {
                if ((flags & Opcodes.ACC_STATIC) != 0) {
                    hasStatic = true;
                } else {
                    hasInstance = true;
                }
                allLocations.add(locEntry.getKey());
            }
        }

        if (hasStatic && hasInstance) {
            reporter.report(new Hazard(
                    Hazard.Type.STATIC_INSTANCE_MISMATCH,
                    Hazard.Severity.WARNING,
                    targetClassName,
                    methodSignature,
                    allLocations
            ));
        }
    }

    public Map<String, List<ClassLocation>> getDuplicateClasses() {
        return duplicateClasses;
    }

}
