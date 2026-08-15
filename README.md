# shady

Catch latent JVM linkage failures before the broken code path runs.

## What Shady detects

Shady is a Java agent that indexes the effective runtime classpath, scans bytecode call sites, and
warns when the class the JVM will resolve does not contain the method a caller was compiled against.
It analyzes classes at startup as well as classes presented to the instrumentation transformer.

This is intentionally broader than duplicate-class detection. A common failure has two different
artifacts that are each present only once but are binary-incompatible with one another:

```text
netty-codec-http 4.1.125  --calls-->  ZlibCodecFactory.newZlibDecoder(ZlibWrapper, int)
netty-codec      4.1.119  --provides-> no such overload
```

That graph throws `NoSuchMethodError` only when the affected decompression path executes. Shady
reports the expected call in Java-readable form, the effective runtime artifact, and any same-name
methods that are actually available there.

It also retains duplicate-FQN reporting, follows indexed superclass and interface methods, includes
inner classes, and scans libraries nested under `BOOT-INF/lib` in Spring Boot executable JARs.

## Build and use

Requirements: Java 11+ and Maven 3.6+.

```bash
mvn clean package
java -javaagent:target/shady-1.0-SNAPSHOT.jar -jar your-application.jar
```

Example warning:

```text
[Shady] WARNING: Linkage hazard detected!
  Caller:   handmade.app.Consumer.main(java.lang.String[]): void
  Expected: handmade.lib.Parser.decode(java.lang.String, int): java.lang.String
  Actual:   no exact method in handmade.lib.Parser
  From:     /path/to/handmade-library-v1.jar
  Available same-name methods:
    - handmade.lib.Parser.decode(java.lang.String): java.lang.String
  Impact:   this call will throw NoSuchMethodError
```

## Tests

```bash
mvn test
```

The regression suite resolves the real Spring Boot 3.4.4 dependency graph with
`netty-codec-http:4.1.125.Final` and asserts that Maven selected `netty-codec:4.1.119.Final`. It then
requires Shady to report that exact caller/target mismatch. A black-box test also builds a consumer
and two tiny library JARs, launches the packaged agent, and verifies both the broken v1 runtime and
the compatible v2 control. Synthetic tests cover inherited methods, inner classes, duplicate
reporting, and Spring Boot nested libraries.

## Scope

Shady currently targets missing-method linkage. If a referenced target class is absent from the
indexed classpath, it is left alone because a custom class loader or optional dependency may supply
it. Multi-release JAR entries under `META-INF/versions` are not yet modeled.

## License

Apache License 2.0 — see `LICENSE`.
