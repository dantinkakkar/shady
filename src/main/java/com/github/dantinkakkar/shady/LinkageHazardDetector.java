package com.github.dantinkakkar.shady;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Detects method linkage hazards against the effective runtime classpath.
 *
 * <p>The detector indexes every class before validating call sites. This catches references in
 * lazily loaded classes and, unlike duplicate-only analysis, detects calls from one artifact into
 * an incompatible version of another artifact.</p>
 */
public class LinkageHazardDetector {

    private final Map<String, List<ClassDefinition>> definitionsByClass = new LinkedHashMap<>();
    private final Map<String, List<ClassLocation>> duplicateClasses = new ConcurrentHashMap<>();
    private final Set<String> warningKeys = ConcurrentHashMap.newKeySet();
    private final Set<String> issuedWarnings = ConcurrentHashMap.newKeySet();
    private final Set<LinkageHazard> detectedHazards = ConcurrentHashMap.newKeySet();
    private final Map<String, Resolution> jdkResolutionCache = new ConcurrentHashMap<>();

    private volatile Map<String, ClassDefinition> effectiveClasses = Collections.emptyMap();

    /**
     * A class definition found on the runtime classpath.
     */
    public static final class ClassLocation {
        private final String location;
        private final String className;

        ClassLocation(String location, String className) {
            this.location = location;
            this.className = className;
        }

        public String getLocation() {
            return location;
        }

        public String getClassName() {
            return className;
        }

        @Override
        public String toString() {
            return location + "!" + className;
        }
    }

    /**
     * A concrete missing-method hazard, including both sides of the linkage.
     */
    public static final class LinkageHazard {
        private final String targetClassName;
        private final String methodSignature;
        private final String callerSignature;
        private final String targetLocation;
        private final List<String> availableMethodSignatures;

        LinkageHazard(String targetClassName, String methodSignature,
                      String callerSignature, String targetLocation,
                      List<String> availableMethodSignatures) {
            this.targetClassName = targetClassName;
            this.methodSignature = methodSignature;
            this.callerSignature = callerSignature;
            this.targetLocation = targetLocation;
            this.availableMethodSignatures = Collections.unmodifiableList(
                    new ArrayList<>(availableMethodSignatures));
        }

        public String getTargetClassName() {
            return targetClassName;
        }

        public String getMethodSignature() {
            return methodSignature;
        }

        public String getCallerSignature() {
            return callerSignature;
        }

        public String getTargetLocation() {
            return targetLocation;
        }

        /**
         * Same-name methods declared by the effective runtime class. These are diagnostic
         * alternatives only; JVM linkage still requires an exact descriptor match.
         */
        public List<String> getAvailableMethodSignatures() {
            return availableMethodSignatures;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof LinkageHazard)) {
                return false;
            }
            LinkageHazard that = (LinkageHazard) other;
            return Objects.equals(targetClassName, that.targetClassName)
                    && Objects.equals(methodSignature, that.methodSignature)
                    && Objects.equals(callerSignature, that.callerSignature)
                    && Objects.equals(targetLocation, that.targetLocation)
                    && Objects.equals(availableMethodSignatures,
                            that.availableMethodSignatures);
        }

        @Override
        public int hashCode() {
            return Objects.hash(targetClassName, methodSignature, callerSignature,
                    targetLocation, availableMethodSignatures);
        }

        @Override
        public String toString() {
            return callerSignature + " -> " + targetClassName + "." + methodSignature
                    + " (resolved target: " + targetLocation
                    + ", available same-name methods: " + availableMethodSignatures + ")";
        }
    }

    private static final class ClassDefinition {
        private final String className;
        private final String superClassName;
        private final List<String> interfaces;
        private final Set<String> methods;
        private final List<MethodInvocation> invocations;
        private final String location;

        private ClassDefinition(String className, String superClassName, List<String> interfaces,
                                Set<String> methods, List<MethodInvocation> invocations,
                                String location) {
            this.className = className;
            this.superClassName = superClassName;
            this.interfaces = interfaces;
            this.methods = methods;
            this.invocations = invocations;
            this.location = location;
        }
    }

    private static final class MethodInvocation {
        private final String targetClassName;
        private final String methodSignature;
        private final String callerSignature;

        private MethodInvocation(String targetClassName, String methodSignature,
                                 String callerSignature) {
            this.targetClassName = targetClassName;
            this.methodSignature = methodSignature;
            this.callerSignature = callerSignature;
        }
    }

    private enum Resolution {
        FOUND,
        MISSING,
        UNKNOWN
    }

    /**
     * Scan the process runtime classpath.
     */
    public synchronized void scanClasspath() {
        scanClasspath(System.getProperty("java.class.path", ""));
    }

    /**
     * Scan an explicit classpath. Exposed so integrations and tests can validate the exact
     * effective artifact set rather than inheriting unrelated process entries.
     */
    public synchronized void scanClasspath(String classpath) {
        clearState();

        System.out.println("[Shady] Indexing effective runtime classpath...");

        String[] entries = classpath.split(Pattern.quote(File.pathSeparator));
        for (String entry : entries) {
            if (entry == null || entry.trim().isEmpty()) {
                continue;
            }

            Path path = Path.of(entry).toAbsolutePath().normalize();
            if (Files.isDirectory(path)) {
                scanDirectory(path);
            } else if (Files.isRegularFile(path) && entry.endsWith(".jar")) {
                scanJar(path);
            }
        }

        buildEffectiveIndex();
        analyzeEffectiveClasses();

        System.out.println("[Shady] Indexed " + effectiveClasses.size() + " effective classes"
                + " and found " + duplicateClasses.size() + " duplicate FQNs");
        System.out.println("[Shady] Linkage analysis complete: " + detectedHazards.size()
                + " hazard(s)");
    }

    private void clearState() {
        definitionsByClass.clear();
        duplicateClasses.clear();
        warningKeys.clear();
        issuedWarnings.clear();
        detectedHazards.clear();
        jdkResolutionCache.clear();
        effectiveClasses = Collections.emptyMap();
    }

    private void scanDirectory(Path root) {
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".class"))
                    .sorted()
                    .forEach(path -> {
                        try {
                            indexClass(Files.readAllBytes(path), root.toString());
                        } catch (IOException e) {
                            System.err.println("[Shady] Could not read class " + path + ": "
                                    + e.getMessage());
                        }
                    });
        } catch (IOException e) {
            System.err.println("[Shady] Could not scan class directory " + root + ": "
                    + e.getMessage());
        }
    }

    private void scanJar(Path jarPath) {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            List<JarEntry> nestedLibraries = new ArrayList<>();
            Enumeration<JarEntry> entries = jar.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }

                String name = entry.getName();
                if (name.startsWith("BOOT-INF/lib/") && name.endsWith(".jar")) {
                    nestedLibraries.add(entry);
                    continue;
                }

                if (!isRuntimeClassEntry(name)) {
                    continue;
                }

                String location = name.startsWith("BOOT-INF/classes/")
                        ? jarPath + "!/BOOT-INF/classes"
                        : jarPath.toString();
                try (InputStream input = jar.getInputStream(entry)) {
                    indexClass(input.readAllBytes(), location);
                }
            }

            for (JarEntry nestedLibrary : nestedLibraries) {
                String nestedLocation = jarPath + "!/" + nestedLibrary.getName();
                try (InputStream input = jar.getInputStream(nestedLibrary)) {
                    scanNestedJar(input, nestedLocation);
                }
            }
        } catch (IOException e) {
            System.err.println("[Shady] Could not scan JAR " + jarPath + ": " + e.getMessage());
        }
    }

    private void scanNestedJar(InputStream input, String location) throws IOException {
        try (JarInputStream nestedJar = new JarInputStream(input)) {
            JarEntry entry;
            while ((entry = nestedJar.getNextJarEntry()) != null) {
                if (!entry.isDirectory() && isRuntimeClassEntry(entry.getName())) {
                    indexClass(nestedJar.readAllBytes(), location);
                }
            }
        }
    }

    private boolean isRuntimeClassEntry(String name) {
        if (!name.endsWith(".class")) {
            return false;
        }
        if (name.startsWith("META-INF/versions/")) {
            return false;
        }
        return !name.equals("module-info.class") && !name.endsWith("/module-info.class");
    }

    private void indexClass(byte[] classBytes, String location) {
        ClassDefinition definition = parseClass(classBytes, location);
        if (definition != null) {
            definitionsByClass.computeIfAbsent(
                    definition.className, ignored -> new ArrayList<>()).add(definition);
        }
    }

    private ClassDefinition parseClass(byte[] classBytes, String location) {
        try {
            ClassReader reader = new ClassReader(classBytes);
            final String[] className = new String[1];
            final String[] superClassName = new String[1];
            final List<String> interfaces = new ArrayList<>();
            final Set<String> methods = new LinkedHashSet<>();
            final List<MethodInvocation> invocations = new ArrayList<>();

            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public void visit(int version, int access, String name, String signature,
                                  String superName, String[] implementedInterfaces) {
                    className[0] = toClassName(name);
                    superClassName[0] = toClassName(superName);
                    if (implementedInterfaces != null) {
                        for (String implementedInterface : implementedInterfaces) {
                            interfaces.add(toClassName(implementedInterface));
                        }
                    }
                }

                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    methods.add(name + descriptor);
                    final String caller = className[0] + "." + name + descriptor;

                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String methodName,
                                                    String methodDescriptor, boolean isInterface) {
                            invocations.add(new MethodInvocation(
                                    toClassName(owner), methodName + methodDescriptor, caller));
                        }

                        @Override
                        public void visitInvokeDynamicInsn(String dynamicName,
                                                           String dynamicDescriptor,
                                                           Handle bootstrapMethodHandle,
                                                           Object... bootstrapMethodArguments) {
                            recordHandle(bootstrapMethodHandle, caller, invocations);
                            if (bootstrapMethodArguments != null) {
                                for (Object argument : bootstrapMethodArguments) {
                                    if (argument instanceof Handle) {
                                        recordHandle((Handle) argument, caller, invocations);
                                    }
                                }
                            }
                        }

                        @Override
                        public void visitLdcInsn(Object value) {
                            if (value instanceof Handle) {
                                recordHandle((Handle) value, caller, invocations);
                            }
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

            if (className[0] == null) {
                return null;
            }

            return new ClassDefinition(
                    className[0],
                    superClassName[0],
                    Collections.unmodifiableList(new ArrayList<>(interfaces)),
                    Collections.unmodifiableSet(new LinkedHashSet<>(methods)),
                    Collections.unmodifiableList(new ArrayList<>(invocations)),
                    location);
        } catch (RuntimeException e) {
            System.err.println("[Shady] Could not parse class from " + location + ": "
                    + e.getMessage());
            return null;
        }
    }

    private static void recordHandle(Handle handle, String caller,
                                     List<MethodInvocation> invocations) {
        if (handle == null) {
            return;
        }

        int tag = handle.getTag();
        if (tag == Opcodes.H_INVOKEVIRTUAL
                || tag == Opcodes.H_INVOKESTATIC
                || tag == Opcodes.H_INVOKESPECIAL
                || tag == Opcodes.H_NEWINVOKESPECIAL
                || tag == Opcodes.H_INVOKEINTERFACE) {
            invocations.add(new MethodInvocation(
                    toClassName(handle.getOwner()),
                    handle.getName() + handle.getDesc(),
                    caller));
        }
    }

    private void buildEffectiveIndex() {
        Map<String, ClassDefinition> selected = new LinkedHashMap<>();

        for (Map.Entry<String, List<ClassDefinition>> entry : definitionsByClass.entrySet()) {
            List<ClassDefinition> definitions = entry.getValue();
            if (definitions.isEmpty()) {
                continue;
            }

            selected.put(entry.getKey(), definitions.get(0));

            if (definitions.size() > 1) {
                List<ClassLocation> locations = new ArrayList<>();
                for (ClassDefinition definition : definitions) {
                    locations.add(new ClassLocation(definition.location, definition.className));
                }
                duplicateClasses.put(entry.getKey(),
                        Collections.unmodifiableList(locations));
            }
        }

        effectiveClasses = Collections.unmodifiableMap(selected);
    }

    private void analyzeEffectiveClasses() {
        for (ClassDefinition definition : effectiveClasses.values()) {
            if (!isJdkClass(definition.className)) {
                analyzeInvocations(definition.invocations);
            }
        }
    }

    /**
     * Analyze a class loaded after startup against the previously indexed effective classpath.
     */
    public void analyzeClass(String className, byte[] classfileBuffer) {
        if (className == null || classfileBuffer == null) {
            return;
        }

        ClassDefinition definition = parseClass(classfileBuffer, "loaded:" + className);
        if (definition != null && !isJdkClass(definition.className)) {
            analyzeInvocations(definition.invocations);
        }
    }

    private void analyzeInvocations(List<MethodInvocation> invocations) {
        for (MethodInvocation invocation : invocations) {
            if (isJdkClass(invocation.targetClassName)) {
                continue;
            }

            ClassDefinition target = effectiveClasses.get(invocation.targetClassName);
            if (target == null) {
                // A custom class loader or optional dependency may supply it. Missing-class
                // analysis is deliberately outside the current NoSuchMethodError scope.
                continue;
            }

            Resolution resolution = resolveMethod(
                    invocation.targetClassName,
                    invocation.methodSignature,
                    new HashSet<>());

            if (resolution == Resolution.MISSING) {
                issueWarning(invocation, target);
            }
        }
    }

    private Resolution resolveMethod(String className, String methodSignature,
                                     Set<String> visited) {
        if (className == null || !visited.add(className)) {
            return Resolution.MISSING;
        }

        if (isJdkClass(className)) {
            return resolveJdkMethod(className, methodSignature);
        }

        ClassDefinition definition = effectiveClasses.get(className);
        if (definition == null) {
            return Resolution.UNKNOWN;
        }

        if (definition.methods.contains(methodSignature)) {
            return Resolution.FOUND;
        }

        if (methodSignature.startsWith("<init>") || methodSignature.startsWith("<clinit>")) {
            return Resolution.MISSING;
        }

        Resolution aggregate = Resolution.MISSING;

        if (definition.superClassName != null) {
            Resolution parent = resolveMethod(
                    definition.superClassName, methodSignature, visited);
            if (parent == Resolution.FOUND) {
                return Resolution.FOUND;
            }
            if (parent == Resolution.UNKNOWN) {
                aggregate = Resolution.UNKNOWN;
            }
        }

        for (String implementedInterface : definition.interfaces) {
            Resolution parent = resolveMethod(
                    implementedInterface, methodSignature, visited);
            if (parent == Resolution.FOUND) {
                return Resolution.FOUND;
            }
            if (parent == Resolution.UNKNOWN) {
                aggregate = Resolution.UNKNOWN;
            }
        }

        return aggregate;
    }

    private Resolution resolveJdkMethod(String className, String methodSignature) {
        String cacheKey = className + "." + methodSignature;
        return jdkResolutionCache.computeIfAbsent(
                cacheKey, ignored -> inspectJdkMethod(className, methodSignature));
    }

    private Resolution inspectJdkMethod(String className, String methodSignature) {
        try {
            Class<?> type = Class.forName(
                    className, false, LinkageHazardDetector.class.getClassLoader());
            Set<Class<?>> visited = new HashSet<>();
            return containsReflectiveMethod(type, methodSignature, visited)
                    ? Resolution.FOUND : Resolution.MISSING;
        } catch (LinkageError | ClassNotFoundException | SecurityException e) {
            return Resolution.UNKNOWN;
        }
    }

    private boolean containsReflectiveMethod(Class<?> type, String methodSignature,
                                             Set<Class<?>> visited) {
        if (type == null || !visited.add(type)) {
            return false;
        }

        for (Method method : type.getDeclaredMethods()) {
            if ((method.getName() + Type.getMethodDescriptor(method)).equals(methodSignature)) {
                return true;
            }
        }

        if (methodSignature.startsWith("<init>")) {
            for (Constructor<?> constructor : type.getDeclaredConstructors()) {
                if (("<init>" + Type.getConstructorDescriptor(constructor))
                        .equals(methodSignature)) {
                    return true;
                }
            }
            return false;
        }

        if (containsReflectiveMethod(type.getSuperclass(), methodSignature, visited)) {
            return true;
        }

        for (Class<?> implementedInterface : type.getInterfaces()) {
            if (containsReflectiveMethod(implementedInterface, methodSignature, visited)) {
                return true;
            }
        }

        return false;
    }

    private void issueWarning(MethodInvocation invocation, ClassDefinition target) {
        String warningKey = invocation.callerSignature + " -> "
                + invocation.targetClassName + "." + invocation.methodSignature;
        if (!warningKeys.add(warningKey)) {
            return;
        }

        List<String> availableMethods = findSameNameMethods(
                target, invocation.methodSignature);
        LinkageHazard hazard = new LinkageHazard(
                invocation.targetClassName,
                invocation.methodSignature,
                invocation.callerSignature,
                target.location,
                availableMethods);

        detectedHazards.add(hazard);
        issuedWarnings.add(hazard.toString());

        System.err.println("[Shady] WARNING: Linkage hazard detected!");
        System.err.println("  Caller:   " + formatCaller(hazard.callerSignature));
        System.err.println("  Expected: " + formatMethod(
                hazard.targetClassName, hazard.methodSignature));
        System.err.println("  Actual:   no exact method in " + hazard.targetClassName);
        System.err.println("  From:     " + hazard.targetLocation);
        if (hazard.availableMethodSignatures.isEmpty()) {
            System.err.println("  Available same-name methods: (none)");
        } else {
            System.err.println("  Available same-name methods:");
            for (String availableMethod : hazard.availableMethodSignatures) {
                System.err.println("    - " + formatMethod(
                        hazard.targetClassName, availableMethod));
            }
        }
        System.err.println("  Impact:   this call will throw NoSuchMethodError");
    }

    private static List<String> findSameNameMethods(ClassDefinition target,
                                                    String expectedMethodSignature) {
        String expectedName = methodName(expectedMethodSignature);
        List<String> matches = new ArrayList<>();
        for (String availableMethod : target.methods) {
            if (expectedName.equals(methodName(availableMethod))) {
                matches.add(availableMethod);
            }
        }
        Collections.sort(matches);
        return matches;
    }

    private static String formatCaller(String callerSignature) {
        int descriptorStart = callerSignature.indexOf('(');
        int ownerSeparator = callerSignature.lastIndexOf('.', descriptorStart);
        if (descriptorStart < 0 || ownerSeparator < 0) {
            return callerSignature;
        }
        return formatMethod(
                callerSignature.substring(0, ownerSeparator),
                callerSignature.substring(ownerSeparator + 1));
    }

    private static String formatMethod(String owner, String methodSignature) {
        int descriptorStart = methodSignature.indexOf('(');
        if (descriptorStart < 0) {
            return owner + "." + methodSignature;
        }

        String name = methodSignature.substring(0, descriptorStart);
        String descriptor = methodSignature.substring(descriptorStart);
        try {
            Type[] arguments = Type.getArgumentTypes(descriptor);
            Type returnType = Type.getReturnType(descriptor);
            StringBuilder formatted = new StringBuilder(owner)
                    .append('.').append(name).append('(');
            for (int index = 0; index < arguments.length; index++) {
                if (index > 0) {
                    formatted.append(", ");
                }
                formatted.append(arguments[index].getClassName());
            }
            return formatted.append("): ")
                    .append(returnType.getClassName())
                    .toString();
        } catch (IllegalArgumentException e) {
            return owner + "." + methodSignature;
        }
    }

    private static String methodName(String methodSignature) {
        int descriptorStart = methodSignature.indexOf('(');
        return descriptorStart < 0
                ? methodSignature : methodSignature.substring(0, descriptorStart);
    }

    private static String toClassName(String internalName) {
        return internalName == null ? null : internalName.replace('/', '.');
    }

    private static boolean isJdkClass(String className) {
        return className != null && (className.startsWith("java.")
                || className.startsWith("javax.")
                || className.startsWith("jdk.")
                || className.startsWith("sun.")
                || className.startsWith("com.sun."));
    }

    public Map<String, List<ClassLocation>> getDuplicateClasses() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(duplicateClasses));
    }

    public Set<String> getIssuedWarnings() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(issuedWarnings));
    }

    public Set<LinkageHazard> getDetectedHazards() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(detectedHazards));
    }
}
