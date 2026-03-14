package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.AgentConfig;
import com.github.dantinkakkar.shady.HazardReporter;
import com.github.dantinkakkar.shady.JDKMethodRegistry;
import com.github.dantinkakkar.shady.LinkageHazardDetector;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class JDKMethodRegistryTest {

    @Test
    public void create_scansJrt_containsStringAndObjectMethods() {
        JDKMethodRegistry registry = JDKMethodRegistry.create();
        if (registry.isEmpty()) return;

        assertTrue(registry.isJdkClass("java.lang.String"));
        assertTrue(registry.hasMethod("java.lang.String", "length()I"));
        assertTrue(registry.hasMethod("java.lang.String", "charAt(I)C"));
        assertTrue(registry.isJdkClass("java.lang.Object"));
        assertTrue(registry.hasMethod("java.lang.Object", "toString()Ljava/lang/String;"));
    }

    @Test
    public void isJdkClass_applicationClass_returnsFalse() {
        JDKMethodRegistry registry = JDKMethodRegistry.create();
        if (registry.isEmpty()) return;

        assertFalse(registry.isJdkClass("com.example.NotAJdkClass"));
        assertFalse(registry.hasMethod("com.example.NotAJdkClass", "foo()V"));
    }

    @Test
    public void analyzeClass_jdkMethodMissingFromRegistry_reportsJdkRemoval() {
        Map<String, Set<String>> map = new HashMap<>();
        map.put("java.lang.Object", new HashSet<>(Arrays.asList(
                "hashCode()I", "equals(Ljava/lang/Object;)Z")));

        JDKMethodRegistry mockRegistry = JDKMethodRegistry.forTesting(map);
        AgentConfig config = new AgentConfig(null);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        HazardReporter reporter = new HazardReporter(config, new PrintStream(output));
        LinkageHazardDetector detector = new LinkageHazardDetector(config, reporter, mockRegistry);

        detector.analyzeClass("com/example/TestToStringCaller", generateToStringCaller());

        String warnings = output.toString();
        assertTrue(warnings.contains("JDK API removal"), "Should detect JDK API removal for toString");
        assertTrue(warnings.contains("toString"), "Should mention toString in warning");
    }

    @Test
    public void forTesting_customMap_queriesReturnExpectedResults() {
        Map<String, Set<String>> map = new HashMap<>();
        map.put("test.Class", new HashSet<>(Arrays.asList("method()V")));

        JDKMethodRegistry registry = JDKMethodRegistry.forTesting(map);

        assertTrue(registry.isJdkClass("test.Class"));
        assertTrue(registry.hasMethod("test.Class", "method()V"));
        assertFalse(registry.hasMethod("test.Class", "other()V"));
    }

    private byte[] generateToStringCaller() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "com/example/TestToStringCaller",
                null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "callToString", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "toString",
                "()Ljava/lang/String;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
