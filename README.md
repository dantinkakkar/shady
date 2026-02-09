# shady

Catch lazy linkage issues from shaded classes within dependency manifests in your Java application, at runtime.

## What is Shady?

Shady is a Java agent that detects latent JVM linkage hazards at startup. It:

1. **Enumerates runtime classpath JARs** - Scans all JARs on the classpath
2. **Finds duplicate FQNs** - Identifies classes that exist in multiple JARs (common with shading)
3. **Diffs method sets** - Compares **all methods** (public, protected, package-private, and private) across different versions of the same class
4. **Scans bytecode** - Uses ASM to analyze loaded bytecode for method call sites
5. **Builds call graphs** - Tracks method invocations to detect deeply nested dependency conflicts
6. **Warns about hazards** - Emits warnings when code calls methods that don't exist in all versions (without crashing)
7. **Detects transitive hazards** - Identifies linkage issues in deeply nested method call chains, including private method calls

## Why do I need this?

When dependencies shade classes or when you have version conflicts, you can end up with multiple versions of the same class on your classpath. Which version gets loaded is often non-deterministic. If code tries to call a method that exists in one version but not another, you'll get a `NoSuchMethodError` at runtime - but only if that code path is executed.

### Transitive Linkage Hazards

Shady now also detects **deeply nested dependency conflicts** where:
- A method exists in all versions of a duplicate class
- But that method internally calls another method deeper in the dependency tree
- And that deeper method doesn't exist in all versions
- This includes calls to private, package-private, protected, and public methods

**Example:** When including both `spring-boot-starter-webflux:3.4.4` and `io.netty:netty-codec-http:4.1.125.Final`, the `ZlibCodecFactory` class may have the same public API in both versions, but internally they call different helper methods (which may be private) that only exist in one version. Shady now detects these transitive hazards by analyzing the complete call chain.

Shady detects these issues proactively at startup, before they cause production failures.

## Quick Start

### Build

```bash
mvn clean package
```

This creates `target/shady-1.0-SNAPSHOT.jar` with the agent.

### Usage

Run your Java application with the agent:

```bash
java -javaagent:shady-1.0-SNAPSHOT.jar -jar your-application.jar
```

### Example Output

When Shady detects a linkage hazard:

**Direct Hazard:**
```
[Shady] Java agent started - detecting linkage hazards...
[Shady] Scanning classpath for duplicate classes...
[Shady] Found 2 duplicate classes on classpath
[Shady] WARNING: Linkage hazard detected!
  Class: com.example.duplicate.DuplicateClass
  Method: methodB()V
  Method is missing in: [/path/to/library-v2.jar]
  Method is present in: [/path/to/library-v1.jar]
```

**Transitive Hazard (Deeply Nested):**
```
[Shady] WARNING: Linkage hazard detected!
  Class: io.netty.handler.codec.compression.ZlibEncoderHelper
  Method: createZlibEncoder()Ljava/lang/Object;
  Method is missing in: [/path/to/spring-boot-webflux.jar]
  Method is present in: [/path/to/netty-codec-http.jar]
  Detection depth: 1 (transitive call)
  Call chain: io.netty.handler.codec.compression.ZlibCodecFactory.newZlibEncoder()Ljava/lang/Object; -> io.netty.handler.codec.compression.ZlibEncoderHelper.createZlibEncoder()Ljava/lang/Object;
```

## Testing

The project includes comprehensive JUnit 5 tests that:

- Create test JARs with duplicate classes but different methods
- Verify the agent detects the duplicates
- Verify warnings are issued for missing methods
- Verify no warnings for methods present in all versions
- Test transitive hazard detection with simulated real-world scenarios (e.g., ZlibCodecFactory)

Run tests:

```bash
mvn test
```

The tests automatically run with the `-javaagent` flag configured in Maven Surefire.

## How It Works

1. **Startup**: The agent's `premain` method is called when the JVM starts
2. **Classpath Scanning**: All JAR files on the classpath are enumerated and scanned for `.class` files
3. **Duplicate Detection**: Classes appearing in multiple JARs are identified
4. **Method Extraction**: For each duplicate, **all methods** (public, protected, package-private, and private) are extracted using ASM to ensure complete coverage of the call chain
5. **Call Graph Construction**: As classes are loaded, method invocations are tracked to build a call graph
6. **Bytecode Analysis**: As classes are loaded, their bytecode is analyzed for method calls
7. **Hazard Detection**: If a call site invokes a method missing in any version, a warning is emitted
8. **Transitive Analysis**: For duplicate classes, methods are analyzed recursively through the entire call graph, stopping only at standard library classes or cyclic references. Results are cached for performance.

The agent uses:
- **Java Instrumentation API** for bytecode transformation hooks
- **ASM library** for bytecode analysis (shaded to avoid conflicts)
- **Concurrent data structures** for thread-safe tracking
- **Intelligent depth traversal** that stops at JDK classes (java.*, javax.*, etc.) to limit scope
- **Complete method analysis** including private methods to catch all potential linkage issues

## CI/CD

The project includes GitHub Actions CI that:
- Builds the agent JAR
- Runs all tests with the `-javaagent` flag
- Validates the agent works correctly

See `.github/workflows/ci.yml` for details.

## Requirements

- Java 11+
- Maven 3.6+

## License

Apache License 2.0 - See LICENSE file for details.

