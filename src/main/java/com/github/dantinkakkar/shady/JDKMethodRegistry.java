package com.github.dantinkakkar.shady;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class JDKMethodRegistry {
    private final Map<String, Set<String>> classMethodMap;

    private JDKMethodRegistry(Map<String, Set<String>> classMethodMap) {
        this.classMethodMap = classMethodMap;
    }

    public static JDKMethodRegistry forTesting(Map<String, Set<String>> classMethodMap) {
        return new JDKMethodRegistry(classMethodMap);
    }

    public static JDKMethodRegistry create() {
        Map<String, Set<String>> map = new ConcurrentHashMap<>();
        try {
            FileSystem jrt = FileSystems.getFileSystem(URI.create("jrt:/"));
            Path modulesPath = jrt.getPath("/modules");

            try (Stream<Path> paths = Files.walk(modulesPath)) {
                paths.filter(p -> p.toString().endsWith(".class"))
                     .forEach(p -> {
                         try (InputStream is = Files.newInputStream(p)) {
                             ClassReader reader = new ClassReader(is);
                             String className = reader.getClassName().replace('/', '.');
                             Set<String> methods = new HashSet<>();

                             reader.accept(new ClassVisitor(Opcodes.ASM9) {
                                 @Override
                                 public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                                   String signature, String[] exceptions) {
                                     boolean isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
                                     boolean isProtected = (access & Opcodes.ACC_PROTECTED) != 0;
                                     if (isPublic || isProtected) {
                                         methods.add(name + descriptor);
                                     }
                                     return null;
                                 }
                             }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

                             map.put(className, methods);
                         } catch (IOException | IllegalArgumentException e) {
                             // Skip unreadable classes
                         }
                     });
            }
        } catch (Exception e) {
            System.err.println("[Shady] JDK method registry unavailable: " + e.getMessage());
            return new JDKMethodRegistry(Collections.emptyMap());
        }

        return new JDKMethodRegistry(map);
    }

    public boolean isJdkClass(String className) {
        return classMethodMap.containsKey(className);
    }

    public boolean hasMethod(String className, String methodSignature) {
        Set<String> methods = classMethodMap.get(className);
        return methods != null && methods.contains(methodSignature);
    }

    public boolean isEmpty() {
        return classMethodMap.isEmpty();
    }

    public int size() {
        return classMethodMap.size();
    }
}
