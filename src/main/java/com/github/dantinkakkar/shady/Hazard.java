package com.github.dantinkakkar.shady;

import java.util.*;

public class Hazard {
    public enum Type {
        MISSING_METHOD, MISSING_FIELD, STATIC_INSTANCE_MISMATCH, JDK_REMOVED_METHOD
    }

    public enum Severity {
        WARNING, ERROR
    }

    private final Type type;
    private final Severity severity;
    private final String targetClass;
    private final String memberSignature;
    private final List<String> locations;

    public Hazard(Type type, Severity severity, String targetClass, String memberSignature, List<String> locations) {
        this.type = type;
        this.severity = severity;
        this.targetClass = targetClass;
        this.memberSignature = memberSignature;
        this.locations = locations != null ? Collections.unmodifiableList(new ArrayList<>(locations)) : Collections.emptyList();
    }

    public String toKey() {
        return targetClass + "." + memberSignature;
    }

    public Type getType() { return type; }
    public Severity getSeverity() { return severity; }
    public String getTargetClass() { return targetClass; }
    public String getMemberSignature() { return memberSignature; }
    public List<String> getLocations() { return locations; }
}
