# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Shady is a Java agent that detects latent JVM linkage hazards at runtime. It scans the classpath for duplicate classes (from shading or version conflicts) and warns when code invokes methods that don't exist in all versions of a duplicate class.

## Build Commands

```bash
mvn clean package              # Build the agent JAR (shaded with ASM)
mvn test                       # Build agent JAR + run tests with agent attached
mvn clean package -DskipTests  # Build without tests
```

**Requirements:** Java 11+, Maven 3.6+

## How Tests Work

Tests are **not standard unit tests** — they require the agent JAR to be built first. The pom.xml handles this by binding `maven-jar-plugin` and `maven-shade-plugin` to the `process-test-classes` phase, so the agent JAR exists before surefire runs. The surefire plugin passes `-javaagent:target/shady-1.0-SNAPSHOT.jar` to the test JVM.

Tests dynamically generate JAR files with ASM (creating duplicate classes with different method sets) and inject them into the classpath at runtime to simulate real linkage hazard scenarios.

There is no way to run a single test class in isolation without the full Maven lifecycle — always use `mvn test`.

## Architecture

**Entry point:** `ShadyAgent.premain()` — registered as `Premain-Class` in the JAR manifest.

**Two-phase detection:**
1. **Startup scan** (`LinkageHazardDetector.scanClasspath()`) — enumerates all classpath JARs, identifies classes that appear in multiple JARs, and extracts their public/protected method signatures using ASM.
2. **Runtime analysis** (`ShadyAgent.ShadyClassTransformer.transform()`) — as the JVM loads classes, their bytecode is parsed with ASM to find method invocations. If a call targets a duplicate class and the method doesn't exist in all versions, a warning is emitted.

**Key design constraint:** The agent never modifies bytecode — `transform()` always returns `null`. It is purely observational.

## ASM Shading

ASM is relocated to `com.github.dantinkakkar.shady.asm` via `maven-shade-plugin` to avoid conflicts with other libraries that may bundle ASM on the classpath.
