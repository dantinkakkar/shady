package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.AgentConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AgentConfigTest {

    @Test
    public void constructor_nullArgs_allDefaultValues() {
        AgentConfig config = new AgentConfig(null);

        assertFalse(config.isDetectJdkRemovals());
        assertFalse(config.isFailOnHazard());
        assertEquals("text", config.getOutputFormat());
        assertNull(config.getOutputFile());
        assertTrue(config.getIncludes().isEmpty());
        assertTrue(config.getExcludes().isEmpty());
    }

    @Test
    public void constructor_emptyString_allDefaultValues() {
        AgentConfig config = new AgentConfig("");

        assertFalse(config.isDetectJdkRemovals());
        assertFalse(config.isFailOnHazard());
        assertEquals("text", config.getOutputFormat());
    }

    @Test
    public void constructor_multipleKeyValuePairs_allValuesParsed() {
        AgentConfig config = new AgentConfig("detectJdkRemovals=true,outputFormat=json,failOnHazard=true");

        assertTrue(config.isDetectJdkRemovals());
        assertEquals("json", config.getOutputFormat());
        assertTrue(config.isFailOnHazard());
    }

    @Test
    public void constructor_outputFileArg_pathExtracted() {
        AgentConfig config = new AgentConfig("outputFile=/tmp/shady-output.txt");

        assertEquals("/tmp/shady-output.txt", config.getOutputFile());
    }

    @Test
    public void shouldAnalyze_includesAndExcludes_filtersCorrectly() {
        AgentConfig config = new AgentConfig("includes=com.example:org.foo,excludes=com.example.internal");

        assertTrue(config.shouldAnalyze("com.example.MyClass"));
        assertTrue(config.shouldAnalyze("org.foo.Bar"));
        assertFalse(config.shouldAnalyze("com.example.internal.Secret"));
        assertFalse(config.shouldAnalyze("net.other.Thing"));
    }

    @Test
    public void shouldAnalyze_noFilters_acceptsEverything() {
        AgentConfig config = new AgentConfig(null);

        assertTrue(config.shouldAnalyze("anything.goes.Here"));
    }

    @Test
    public void shouldAnalyze_slashSeparatedInput_normalisesToDots() {
        AgentConfig config = new AgentConfig("excludes=com.example.internal");

        assertFalse(config.shouldAnalyze("com/example/internal/Secret"));
    }
}
