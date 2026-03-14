package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.AgentConfig;
import com.github.dantinkakkar.shady.Hazard;
import com.github.dantinkakkar.shady.HazardReporter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class HazardReporterTest {

    @Test
    public void report_textFormat_emitsHumanReadableWarning() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        HazardReporter reporter = new HazardReporter(new AgentConfig(null), new PrintStream(baos));

        reporter.report(new Hazard(Hazard.Type.MISSING_METHOD, Hazard.Severity.WARNING,
                "com.example.Test", "foo()V",
                Collections.singletonList("/path/to/jar")));

        String output = baos.toString();
        assertTrue(output.contains("[Shady] WARNING: Linkage hazard detected!"));
        assertTrue(output.contains("Class: com.example.Test"));
        assertTrue(output.contains("Method: foo()V"));
        assertTrue(output.contains("Method is missing in:"));
    }

    @Test
    public void report_jsonFormat_emitsStructuredJsonLine() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        HazardReporter reporter = new HazardReporter(
                new AgentConfig("outputFormat=json"), new PrintStream(baos));

        reporter.report(new Hazard(Hazard.Type.MISSING_METHOD, Hazard.Severity.WARNING,
                "com.example.Test", "foo()V",
                Collections.singletonList("/path/to/jar")));

        String output = baos.toString();
        assertTrue(output.contains("\"type\":\"MISSING_METHOD\""));
        assertTrue(output.contains("\"class\":\"com.example.Test\""));
        assertTrue(output.contains("\"member\":\"foo()V\""));
        assertTrue(output.contains("\"severity\":\"WARNING\""));
        assertTrue(output.contains("\"locations\":["));
    }

    @Test
    public void printSummary_multipleHazardTypes_showsCountsByType() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        HazardReporter reporter = new HazardReporter(new AgentConfig(null), new PrintStream(baos));
        reporter.report(new Hazard(Hazard.Type.MISSING_METHOD, Hazard.Severity.WARNING,
                "A", "m()V", Collections.emptyList()));
        reporter.report(new Hazard(Hazard.Type.MISSING_FIELD, Hazard.Severity.WARNING,
                "B", "f:I", Collections.emptyList()));
        baos.reset();

        reporter.printSummary();

        String summary = baos.toString();
        assertTrue(summary.contains("[Shady] === Summary: 2 hazards found (1 methods, 1 fields) ==="),
                "Got: " + summary);
    }
}
