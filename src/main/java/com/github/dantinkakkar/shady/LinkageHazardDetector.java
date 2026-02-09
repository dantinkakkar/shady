package com.github.dantinkakkar.shady;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Detects linkage hazards by scanning the classpath for duplicate classes
 * and analyzing bytecode for method calls that might not exist in all versions.
 */
public class LinkageHazardDetector {
    
    // Map of class name to list of locations where it's found
    private final Map<String, List<ClassLocation>> duplicateClasses = new ConcurrentHashMap<>();
    
    // Map of class name to set of public/protected methods for each location
    private final Map<String, Map<String, Set<String>>> classMethodSets = new ConcurrentHashMap<>();
    
    // Track warnings we've already issued to avoid spam
    private final Set<String> issuedWarnings = ConcurrentHashMap.newKeySet();
    
    // Call graph: Maps method (className.methodName+descriptor) to the methods it calls
    private final Map<String, Set<MethodInvocation>> callGraph = new ConcurrentHashMap<>();
    
    // Map of JAR path to all class names contained within (for analysis)
    private final Map<String, Set<String>> jarContents = new ConcurrentHashMap<>();
    
    /**
     * Represents a location where a class is found.
     */
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
    
    /**
     * Represents a method invocation in the call graph.
     */
    private static class MethodInvocation {
        final String className;
        final String methodSignature;
        
        MethodInvocation(String className, String methodSignature) {
            this.className = className;
            this.methodSignature = methodSignature;
        }
        
        String getFullSignature() {
            return className + "." + methodSignature;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MethodInvocation that = (MethodInvocation) o;
            return Objects.equals(className, that.className) &&
                   Objects.equals(methodSignature, that.methodSignature);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(className, methodSignature);
        }
        
        @Override
        public String toString() {
            return className + "." + methodSignature;
        }
    }
    
    /**
     * Scan the runtime classpath for duplicate classes and analyze their methods.
     */
    public void scanClasspath() {
        System.out.println("[Shady] Scanning classpath for duplicate classes...");
        
        // Get classpath
        String classpath = System.getProperty("java.class.path");
        String[] classpathEntries = classpath.split(File.pathSeparator);
        
        // Map to track all classes: className -> List of jar paths
        Map<String, List<String>> classLocations = new HashMap<>();
        
        // Scan each JAR
        for (String entry : classpathEntries) {
            File file = new File(entry);
            if (file.exists() && file.getName().endsWith(".jar")) {
                scanJar(file, classLocations);
            }
        }
        
        // Find duplicates and analyze them
        for (Map.Entry<String, List<String>> entry : classLocations.entrySet()) {
            String className = entry.getKey();
            List<String> jars = entry.getValue();
            
            if (jars.size() > 1) {
                // Found a duplicate!
                List<ClassLocation> locations = new ArrayList<>();
                for (String jar : jars) {
                    locations.add(new ClassLocation(jar, className));
                }
                duplicateClasses.put(className, locations);
                
                // Analyze methods in each version
                analyzeMethodsInDuplicates(className, jars);
            }
        }
        
        if (!duplicateClasses.isEmpty()) {
            System.out.println("[Shady] Found " + duplicateClasses.size() + " duplicate classes on classpath");
        } else {
            System.out.println("[Shady] No duplicate classes found on classpath");
        }
    }
    
    /**
     * Scan a JAR file for class files.
     */
    private void scanJar(File jarFile, Map<String, List<String>> classLocations) {
        try (JarFile jar = new JarFile(jarFile)) {
            Set<String> classesInJar = new HashSet<>();
            String jarPath = jarFile.getAbsolutePath();
            
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                if (name.endsWith(".class")) {
                    // Extract just the class name (without path) to check for inner classes
                    String classNamePart = name.substring(name.lastIndexOf('/') + 1);
                    
                    // Skip inner classes (those with $ in the class name itself)
                    if (!classNamePart.contains("$")) {
                        // Convert path to class name
                        String className = name.replace("/", ".").substring(0, name.length() - 6);
                        
                        classLocations.computeIfAbsent(className, k -> new ArrayList<>())
                                .add(jarPath);
                        classesInJar.add(className);
                    }
                }
            }
            
            // Store jar contents for later analysis
            jarContents.put(jarPath, classesInJar);
        } catch (IOException e) {
            System.err.println("[Shady] Error scanning JAR " + jarFile + ": " + e.getMessage());
        }
    }
    
    /**
     * Analyze methods in all versions of a duplicate class.
     */
    private void analyzeMethodsInDuplicates(String className, List<String> jars) {
        Map<String, Set<String>> methodsByLocation = new HashMap<>();
        
        for (String jarPath : jars) {
            Set<String> methods = extractPublicProtectedMethods(jarPath, className);
            if (methods != null) {
                methodsByLocation.put(jarPath, methods);
            }
        }
        
        if (!methodsByLocation.isEmpty()) {
            classMethodSets.put(className, methodsByLocation);
        }
    }
    
    /**
     * Extract public and protected methods from a class in a JAR.
     */
    private Set<String> extractPublicProtectedMethods(String jarPath, String className) {
        Set<String> methods = new HashSet<>();
        
        try (JarFile jar = new JarFile(jarPath)) {
            String entryName = className.replace(".", "/") + ".class";
            JarEntry entry = jar.getJarEntry(entryName);
            
            if (entry != null) {
                try (InputStream is = jar.getInputStream(entry)) {
                    ClassReader reader = new ClassReader(is);
                    
                    reader.accept(new ClassVisitor(Opcodes.ASM9) {
                        @Override
                        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                          String signature, String[] exceptions) {
                            // Check if public or protected
                            boolean isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
                            boolean isProtected = (access & Opcodes.ACC_PROTECTED) != 0;
                            
                            if (isPublic || isProtected) {
                                methods.add(name + descriptor);
                            }
                            
                            return null;
                        }
                    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                }
            }
        } catch (IOException e) {
            System.err.println("[Shady] Error reading class " + className + " from " + jarPath);
        }
        
        return methods;
    }
    
    /**
     * Analyze a class's bytecode for potential linkage hazards.
     */
    public void analyzeClass(String className, byte[] classfileBuffer) {
        if (className == null || classfileBuffer == null) {
            return;
        }
        
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            
            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                private String currentClassName;
                
                @Override
                public void visit(int version, int access, String name, String signature,
                                  String superName, String[] interfaces) {
                    currentClassName = name.replace("/", ".");
                    super.visit(version, access, name, signature, superName, interfaces);
                }
                
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    final String currentMethodSig = currentClassName + "." + name + descriptor;
                    
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String name,
                                                     String descriptor, boolean isInterface) {
                            String targetClassName = owner.replace("/", ".");
                            String targetMethodSig = name + descriptor;
                            
                            // Build call graph
                            MethodInvocation invocation = new MethodInvocation(targetClassName, targetMethodSig);
                            callGraph.computeIfAbsent(currentMethodSig, k -> ConcurrentHashMap.newKeySet())
                                    .add(invocation);
                            
                            // Check for direct hazards
                            checkMethodCall(targetClassName, targetMethodSig);
                            
                            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            
        } catch (Exception e) {
            // Don't crash - just log
            System.err.println("[Shady] Error analyzing class " + className + ": " + e.getMessage());
        }
    }
    
    /**
     * Check if a method call might be hazardous (direct check only).
     */
    private void checkMethodCall(String targetClassName, String methodSignature) {
        checkMethodCallTransitive(targetClassName, methodSignature, new HashSet<>(), 0, null);
    }
    
    /**
     * Check if a method call might be hazardous, including transitive calls.
     * 
     * @param targetClassName the class containing the method
     * @param methodSignature the method signature being called
     * @param visited set of already visited methods to prevent cycles
     * @param depth current depth in the call chain
     * @param callChain the chain of calls that led to this point (for debugging)
     */
    private void checkMethodCallTransitive(String targetClassName, String methodSignature, 
                                          Set<String> visited, int depth, List<String> callChain) {
        // Limit depth to prevent excessive recursion
        if (depth > 5) {
            return;
        }
        
        String fullMethodSig = targetClassName + "." + methodSignature;
        
        // Prevent infinite loops in cyclic call graphs
        if (visited.contains(fullMethodSig)) {
            return;
        }
        visited.add(fullMethodSig);
        
        // Initialize call chain if needed
        if (callChain == null) {
            callChain = new ArrayList<>();
        }
        callChain.add(fullMethodSig);
        
        // Check if the target class has duplicates
        Map<String, Set<String>> methodsByLocation = classMethodSets.get(targetClassName);
        
        if (methodsByLocation != null && methodsByLocation.size() > 1) {
            // Check if the method exists in all versions
            boolean missingInSome = false;
            List<String> missingLocations = new ArrayList<>();
            List<String> presentLocations = new ArrayList<>();
            
            for (Map.Entry<String, Set<String>> entry : methodsByLocation.entrySet()) {
                if (!entry.getValue().contains(methodSignature)) {
                    missingInSome = true;
                    missingLocations.add(entry.getKey());
                } else {
                    presentLocations.add(entry.getKey());
                }
            }
            
            if (missingInSome) {
                String warningKey = fullMethodSig;
                
                // Only warn once per method
                if (issuedWarnings.add(warningKey)) {
                    System.err.println("[Shady] WARNING: Linkage hazard detected!");
                    System.err.println("  Class: " + targetClassName);
                    System.err.println("  Method: " + methodSignature);
                    System.err.println("  Method is missing in: " + missingLocations);
                    System.err.println("  Method is present in: " + presentLocations);
                    
                    if (depth > 0) {
                        System.err.println("  Detection depth: " + depth + " (transitive call)");
                        System.err.println("  Call chain: " + String.join(" -> ", callChain));
                    }
                }
            }
            
            // If the method exists in at least one version, analyze its transitive calls
            // We need to check what this method calls in the versions where it exists
            if (!presentLocations.isEmpty()) {
                analyzeTransitiveCalls(presentLocations.get(0), targetClassName, methodSignature, 
                                     visited, depth, new ArrayList<>(callChain));
            }
        } else {
            // Even if not a duplicate, analyze transitive calls from this method
            // This helps catch cases where a non-duplicate calls a duplicate deeper in the tree
            analyzeTransitiveCallsForNonDuplicate(targetClassName, methodSignature, 
                                                 visited, depth, new ArrayList<>(callChain));
        }
    }
    
    /**
     * Analyze transitive calls from a method in a specific JAR.
     */
    private void analyzeTransitiveCalls(String jarPath, String className, String methodSig,
                                       Set<String> visited, int depth, List<String> callChain) {
        // Extract method calls from this specific method in this JAR
        Set<MethodInvocation> calledMethods = extractMethodCalls(jarPath, className, methodSig);
        
        if (calledMethods != null) {
            for (MethodInvocation invocation : calledMethods) {
                checkMethodCallTransitive(invocation.className, invocation.methodSignature,
                                        visited, depth + 1, callChain);
            }
        }
    }
    
    /**
     * Analyze transitive calls for non-duplicate classes using the call graph.
     */
    private void analyzeTransitiveCallsForNonDuplicate(String className, String methodSig,
                                                       Set<String> visited, int depth, 
                                                       List<String> callChain) {
        String fullMethodSig = className + "." + methodSig;
        Set<MethodInvocation> calledMethods = callGraph.get(fullMethodSig);
        
        if (calledMethods != null) {
            for (MethodInvocation invocation : calledMethods) {
                checkMethodCallTransitive(invocation.className, invocation.methodSignature,
                                        visited, depth + 1, callChain);
            }
        }
    }
    
    /**
     * Extract method calls from a specific method in a JAR file.
     */
    private Set<MethodInvocation> extractMethodCalls(String jarPath, String className, String methodSig) {
        Set<MethodInvocation> methodCalls = new HashSet<>();
        
        try (JarFile jar = new JarFile(jarPath)) {
            String entryName = className.replace(".", "/") + ".class";
            JarEntry entry = jar.getJarEntry(entryName);
            
            if (entry != null) {
                try (InputStream is = jar.getInputStream(entry)) {
                    ClassReader reader = new ClassReader(is);
                    
                    reader.accept(new ClassVisitor(Opcodes.ASM9) {
                        @Override
                        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                          String signature, String[] exceptions) {
                            // Check if this is the method we're interested in
                            if ((name + descriptor).equals(methodSig)) {
                                return new MethodVisitor(Opcodes.ASM9) {
                                    @Override
                                    public void visitMethodInsn(int opcode, String owner, String name,
                                                                 String descriptor, boolean isInterface) {
                                        String targetClassName = owner.replace("/", ".");
                                        String targetMethodSig = name + descriptor;
                                        methodCalls.add(new MethodInvocation(targetClassName, targetMethodSig));
                                        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                                    }
                                };
                            }
                            return null;
                        }
                    }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                }
            }
        } catch (IOException e) {
            // Ignore errors - just return empty set
        }
        
        return methodCalls;
    }
    
    /**
     * Get the map of duplicate classes (for testing).
     */
    public Map<String, List<ClassLocation>> getDuplicateClasses() {
        return duplicateClasses;
    }
    
    /**
     * Get the set of issued warnings (for testing).
     */
    public Set<String> getIssuedWarnings() {
        return issuedWarnings;
    }
}
