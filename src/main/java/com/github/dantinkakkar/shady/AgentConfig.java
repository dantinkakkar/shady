package com.github.dantinkakkar.shady;

import java.util.*;

public class AgentConfig {
    private final List<String> includes;
    private final List<String> excludes;
    private final boolean detectJdkRemovals;
    private final String outputFormat;
    private final String outputFile;
    private final boolean failOnHazard;

    public AgentConfig(String agentArgs) {
        Map<String, String> parsed = parseArgs(agentArgs);
        this.includes = parseColonSeparated(parsed.get("includes"));
        this.excludes = parseColonSeparated(parsed.get("excludes"));
        this.detectJdkRemovals = Boolean.parseBoolean(parsed.getOrDefault("detectJdkRemovals", "false"));
        this.outputFormat = parsed.getOrDefault("outputFormat", "text");
        this.outputFile = parsed.get("outputFile");
        this.failOnHazard = Boolean.parseBoolean(parsed.getOrDefault("failOnHazard", "false"));
    }

    private Map<String, String> parseArgs(String agentArgs) {
        Map<String, String> result = new HashMap<>();
        if (agentArgs == null || agentArgs.trim().isEmpty()) {
            return result;
        }
        for (String pair : agentArgs.split(",")) {
            String trimmed = pair.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                result.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
            }
        }
        return result;
    }

    private List<String> parseColonSeparated(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        for (String part : value.split(":")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    public boolean shouldAnalyze(String className) {
        String dotName = className.replace('/', '.');

        if (!includes.isEmpty()) {
            boolean matched = false;
            for (String prefix : includes) {
                if (dotName.startsWith(prefix)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return false;
        }

        for (String prefix : excludes) {
            if (dotName.startsWith(prefix)) {
                return false;
            }
        }

        return true;
    }

    public boolean isDetectJdkRemovals() { return detectJdkRemovals; }
    public String getOutputFormat() { return outputFormat; }
    public String getOutputFile() { return outputFile; }
    public boolean isFailOnHazard() { return failOnHazard; }
    public List<String> getIncludes() { return includes; }
    public List<String> getExcludes() { return excludes; }
}
