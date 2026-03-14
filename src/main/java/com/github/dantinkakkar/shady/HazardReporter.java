package com.github.dantinkakkar.shady;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class HazardReporter {
    private final AgentConfig config;
    private final Map<String, Hazard> hazards = new ConcurrentHashMap<>();
    private final PrintStream output;
    private PrintWriter fileWriter;

    public HazardReporter(AgentConfig config) {
        this(config, System.err);
    }

    public HazardReporter(AgentConfig config, PrintStream output) {
        this.config = config;
        this.output = output;
        if (config.getOutputFile() != null) {
            try {
                this.fileWriter = new PrintWriter(new FileWriter(config.getOutputFile()), true);
            } catch (IOException e) {
                output.println("[Shady] Error opening output file: " + e.getMessage());
            }
        }
    }

    public boolean report(Hazard hazard) {
        String key = hazard.toKey();
        if (hazards.putIfAbsent(key, hazard) != null) {
            return false;
        }
        emit(hazard);
        return true;
    }

    private void emit(Hazard hazard) {
        if ("json".equals(config.getOutputFormat())) {
            writeLine(toJson(hazard));
        } else {
            writeTextWarning(hazard);
        }
    }

    private void writeTextWarning(Hazard hazard) {
        String severityLabel = hazard.getSeverity() == Hazard.Severity.ERROR ? "ERROR" : "WARNING";
        String typeLabel;
        switch (hazard.getType()) {
            case MISSING_METHOD: typeLabel = "Linkage hazard"; break;
            case MISSING_FIELD: typeLabel = "Field access hazard"; break;
            case STATIC_INSTANCE_MISMATCH: typeLabel = "Static/instance mismatch"; break;
            case JDK_REMOVED_METHOD: typeLabel = "JDK API removal hazard"; break;
            default: typeLabel = "Hazard"; break;
        }
        writeLine("[Shady] " + severityLabel + ": " + typeLabel + " detected!");
        writeLine("  Class: " + hazard.getTargetClass());
        String memberType = (hazard.getType() == Hazard.Type.MISSING_FIELD) ? "Field" : "Method";
        writeLine("  " + memberType + ": " + hazard.getMemberSignature());
        if (!hazard.getLocations().isEmpty()) {
            if (hazard.getType() == Hazard.Type.JDK_REMOVED_METHOD) {
                writeLine("  Method not found in current JDK runtime");
            } else if (hazard.getType() == Hazard.Type.STATIC_INSTANCE_MISMATCH) {
                writeLine("  Method has inconsistent static/instance modifiers across: " + hazard.getLocations());
            } else {
                writeLine("  " + memberType + " is missing in: " + hazard.getLocations());
            }
        }
    }

    private String toJson(Hazard hazard) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"type\":\"").append(escapeJson(hazard.getType().name())).append("\"");
        sb.append(",\"class\":\"").append(escapeJson(hazard.getTargetClass())).append("\"");
        sb.append(",\"member\":\"").append(escapeJson(hazard.getMemberSignature())).append("\"");
        sb.append(",\"severity\":\"").append(escapeJson(hazard.getSeverity().name())).append("\"");
        sb.append(",\"locations\":[");
        List<String> locs = hazard.getLocations();
        for (int i = 0; i < locs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(locs.get(i))).append("\"");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private void writeLine(String line) {
        output.println(line);
        if (fileWriter != null) {
            fileWriter.println(line);
        }
    }

    public void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            printSummary();
            if (fileWriter != null) {
                fileWriter.flush();
                fileWriter.close();
            }
            if (config.isFailOnHazard() && !hazards.isEmpty()) {
                Runtime.getRuntime().halt(1);
            }
        }));
    }

    public void printSummary() {
        if (hazards.isEmpty()) {
            return;
        }
        int methods = 0, fields = 0, jdkRemovals = 0, mismatches = 0;
        for (Hazard h : hazards.values()) {
            switch (h.getType()) {
                case MISSING_METHOD: methods++; break;
                case MISSING_FIELD: fields++; break;
                case JDK_REMOVED_METHOD: jdkRemovals++; break;
                case STATIC_INSTANCE_MISMATCH: mismatches++; break;
            }
        }

        if ("json".equals(config.getOutputFormat())) {
            StringBuilder json = new StringBuilder();
            json.append("{\"summary\":{\"total\":").append(hazards.size());
            json.append(",\"methods\":").append(methods);
            json.append(",\"fields\":").append(fields);
            json.append(",\"jdkRemovals\":").append(jdkRemovals);
            json.append(",\"mismatches\":").append(mismatches);
            json.append("}}");
            writeLine(json.toString());
        } else {
            StringBuilder summary = new StringBuilder();
            summary.append("[Shady] === Summary: ").append(hazards.size()).append(" hazards found (");
            List<String> parts = new ArrayList<>();
            if (methods > 0) parts.add(methods + " methods");
            if (fields > 0) parts.add(fields + " fields");
            if (jdkRemovals > 0) parts.add(jdkRemovals + " JDK removals");
            if (mismatches > 0) parts.add(mismatches + " mismatches");
            for (int i = 0; i < parts.size(); i++) {
                if (i > 0) summary.append(", ");
                summary.append(parts.get(i));
            }
            summary.append(") ===");
            writeLine(summary.toString());
        }
    }

    public Collection<Hazard> getHazards() {
        return hazards.values();
    }
}
