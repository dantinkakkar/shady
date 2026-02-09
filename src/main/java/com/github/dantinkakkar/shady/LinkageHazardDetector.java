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
 * 
 * <p>This detector performs static analysis of bytecode to identify potential
 * NoSuchMethodError scenarios before they occur at runtime. It builds a complete call graph
 * by analyzing <strong>ALL loaded classes</strong> (not just duplicates) and tracking
 * <strong>ALL method invocation types</strong> (static, virtual, interface, special).</p>
 * 
 * <p>The analysis recursively follows method calls transitively, even through non-duplicate
 * classes, to detect hazards deep in the dependency tree.</p>
 * 
 * <p><strong>Limitation:</strong> This is a static analysis tool and cannot fully handle
 * dynamic dispatch (polymorphism). Method calls on interfaces or abstract classes are
 * tracked based on the declared type in bytecode, not the actual runtime type. This means
 * some transitive hazards involving different implementations of the same interface may
 * not be detected.</p>
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
    
    // Cache for extracted method calls: (jarPath, className, methodSig) -> Set<MethodInvocation>
    private final Map<MethodCallCacheKey, Set<MethodInvocation>> methodCallCache = new ConcurrentHashMap<>();
    
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
     * Cache key for extracted method calls.
     * Using a proper object instead of string concatenation to avoid collision issues.
     */
    private static class MethodCallCacheKey {
        final String jarPath;
        final String className;
        final String methodSig;
        
        MethodCallCacheKey(String jarPath, String className, String methodSig) {
            this.jarPath = jarPath;
            this.className = className;
            this.methodSig = methodSig;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MethodCallCacheKey that = (MethodCallCacheKey) o;
            return Objects.equals(jarPath, that.jarPath) &&
                   Objects.equals(className, that.className) &&
                   Objects.equals(methodSig, that.methodSig);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(jarPath, className, methodSig);
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
                    }
                }
            }
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
            Set<String> methods = extractAllMethods(jarPath, className);
            if (methods != null) {
                methodsByLocation.put(jarPath, methods);
            }
        }
        
        if (!methodsByLocation.isEmpty()) {
            classMethodSets.put(className, methodsByLocation);
        }
    }
    
    /**
     * Extract all methods (public, protected, package-private, and private) from a class in a JAR.
     * This is necessary because transitive call chains can involve methods of any visibility.
     * For example, a public method might call a private method that doesn't exist in another version.
     */
    private Set<String> extractAllMethods(String jarPath, String className) {
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
                            // Extract all methods regardless of visibility
                            // Skip synthetic and bridge methods as they are compiler-generated
                            boolean isSynthetic = (access & Opcodes.ACC_SYNTHETIC) != 0;
                            boolean isBridge = (access & Opcodes.ACC_BRIDGE) != 0;
                            
                            if (!isSynthetic && !isBridge) {
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
     * 
     * <p>This method is called for EVERY class loaded by the JVM, not just duplicate classes.
     * It builds a complete call graph by tracking all method invocations including:</p>
     * <ul>
     *   <li>Static method calls (INVOKESTATIC)</li>
     *   <li>Virtual method calls (INVOKEVIRTUAL)</li>
     *   <li>Interface method calls (INVOKEINTERFACE)</li>
     *   <li>Special method calls (INVOKESPECIAL - constructors, private methods, super calls)</li>
     * </ul>
     * 
     * <p>Even if the analyzed class is not duplicated, its transitive method calls are followed
     * to detect hazards deeper in the call chain.</p>
     * 
     * @param className the name of the class being analyzed
     * @param classfileBuffer the bytecode of the class
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
        String fullMethodSig = targetClassName + "." + methodSignature;
        
        // Prevent infinite loops in cyclic call graphs
        if (visited.contains(fullMethodSig)) {
            return;
        }
        visited.add(fullMethodSig);
        
        // Stop traversal at standard library classes to limit scope
        if (isStandardLibraryClass(targetClassName)) {
            return;
        }
        
        // Initialize call chain if needed
        if (callChain == null) {
            callChain = new ArrayList<>();
        }
        List<String> currentChain = new ArrayList<>(callChain);
        currentChain.add(fullMethodSig);
        
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
                        System.err.println("  Call chain: " + String.join(" -> ", currentChain));
                    } else {
                        System.err.println("  Detection depth: 0 (direct call)");
                    }
                }
            }
            
            // If the method exists in at least one version, analyze its transitive calls
            // Check all variants to ensure we don't miss hazards
            // Use a fresh visited set for each variant to avoid one variant's traversal
            // preventing another from exploring the same methods
            if (!presentLocations.isEmpty()) {
                for (String jarPath : presentLocations) {
                    Set<String> variantVisited = new HashSet<>(visited);
                    analyzeTransitiveCalls(jarPath, targetClassName, methodSignature, 
                                         variantVisited, depth + 1, currentChain);
                }
            }
        } else {
            // Even if not a duplicate, analyze transitive calls from this method
            // This helps catch cases where a non-duplicate calls a duplicate deeper in the tree
            analyzeTransitiveCallsForNonDuplicate(targetClassName, methodSignature, 
                                                 visited, depth + 1, currentChain);
        }
    }
    
    /**
     * Check if a class is part of the standard library.
     * Standard library classes are unlikely to have linkage issues and traversing them
     * would be expensive and unnecessary.
     * 
     * Includes:
     * - java.* - Core Java classes
     * - javax.* - Java extensions
     * - sun.* - Sun/Oracle internal classes
     * - com.sun.* - Sun/Oracle internal packages
     * - jdk.* - JDK internal modules (Java 9+)
     * 
     * Note: This list covers standard OpenJDK/Oracle JDK. Alternative JVM implementations
     * may have additional packages that should be excluded.
     */
    private boolean isStandardLibraryClass(String className) {
        return className.startsWith("java.") || 
               className.startsWith("javax.") ||
               className.startsWith("sun.") ||
               className.startsWith("com.sun.") ||
               className.startsWith("jdk.");
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
                // Pass a fresh copy of the call chain for each invocation
                checkMethodCallTransitive(invocation.className, invocation.methodSignature,
                                        visited, depth, new ArrayList<>(callChain));
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
                // Pass a fresh copy of the call chain for each invocation
                checkMethodCallTransitive(invocation.className, invocation.methodSignature,
                                        visited, depth, new ArrayList<>(callChain));
            }
        }
    }
    
    /**
     * Extract method calls from a specific method in a JAR file.
     * Results are cached to avoid repeatedly parsing the same methods.
     */
    private Set<MethodInvocation> extractMethodCalls(String jarPath, String className, String methodSig) {
        // Create cache key
        MethodCallCacheKey cacheKey = new MethodCallCacheKey(jarPath, className, methodSig);
        
        // Check cache first
        Set<MethodInvocation> cached = methodCallCache.get(cacheKey);
        if (cached != null) {
            return cached;
        }
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
            // Log the error but don't crash - transitive analysis is best-effort
            System.err.println("[Shady] Warning: Could not analyze transitive calls in " + 
                             className + "." + methodSig + " from " + jarPath + ": " + e.getMessage());
        }
        
        // Cache the result (even if empty)
        methodCallCache.put(cacheKey, methodCalls);
        
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
