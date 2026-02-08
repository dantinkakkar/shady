# shady

Catch lazy linkage issues from shaded classes within dependency manifests in your Java application, at runtime.

## What is Shady?

Shady is a Java agent that detects latent JVM linkage hazards at startup. It:

1. **Enumerates runtime classpath JARs** - Scans all JARs on the classpath
2. **Finds duplicate FQNs** - Identifies classes that exist in multiple JARs (common with shading)
3. **Diffs method sets** - Compares public/protected methods across different versions of the same class
4. **Scans bytecode** - Uses ASM to analyze loaded bytecode for method call sites
5. **Warns about hazards** - Emits warnings when code calls methods that don't exist in all versions (without crashing)

## Why do I need this?

When dependencies shade classes or when you have version conflicts, you can end up with multiple versions of the same class on your classpath. Which version gets loaded is often non-deterministic. If code tries to call a method that exists in one version but not another, you'll get a `NoSuchMethodError` at runtime - but only if that code path is executed.

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

```
[Shady] Java agent started - detecting linkage hazards...
[Shady] Scanning classpath for duplicate classes...
[Shady] Found 2 duplicate classes on classpath
[Shady] WARNING: Linkage hazard detected!
  Class: com.example.duplicate.DuplicateClass
  Method: methodB()V
  Method is missing in: [/path/to/library-v2.jar]
```

## Testing

The project includes comprehensive JUnit 5 tests that:

- Create test JARs with duplicate classes but different methods
- Verify the agent detects the duplicates
- Verify warnings are issued for missing methods
- Verify no warnings for methods present in all versions

Run tests:

```bash
mvn test
```

The tests automatically run with the `-javaagent` flag configured in Maven Surefire.

## How It Works

1. **Startup**: The agent's `premain` method is called when the JVM starts
2. **Classpath Scanning**: All JAR files on the classpath are enumerated and scanned for `.class` files
3. **Duplicate Detection**: Classes appearing in multiple JARs are identified
4. **Method Extraction**: For each duplicate, public/protected methods are extracted using ASM
5. **Bytecode Analysis**: As classes are loaded, their bytecode is analyzed for method calls
6. **Hazard Detection**: If a call site invokes a method missing in any version, a warning is emitted

The agent uses:
- **Java Instrumentation API** for bytecode transformation hooks
- **ASM library** for bytecode analysis (shaded to avoid conflicts)
- **Concurrent data structures** for thread-safe tracking

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

