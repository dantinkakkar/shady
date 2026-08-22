# Current OSS linkage-regression exploration

Status: in progress  
Started: 2026-08-22

## Scope

This branch searches for **ordinary JVM binary-compatibility bugs** in the naturally resolved
runtime graphs of current open-source library releases. It does not investigate security
vulnerabilities, exploits, adversarial inputs, or missing-class behavior.

The target outcome is four or five previously unreported NoSuchMethodError-class regressions
that materially strengthen Shady's core thesis.

## Acceptance bar

A candidate becomes a finding only when all of the following are true:

- the application directly declares the latest stable release available at the time of testing;
- Maven or Gradle naturally resolves the incompatible graph, without manually forcing a bad pair;
- Shady identifies the exact caller, method descriptor, effective target class, and runtime jar;
- a normal application-facing API reaches the predicted call site where practical;
- the JVM failure agrees with Shady's warning;
- an upstream issue/PR search finds no prior report of the same incompatibility;
- the result is checked for scanner limitations such as multi-release jars and classpath-order artifacts.

Static signals that have not passed these checks remain candidates and will not be presented as bugs.

## Resolver controls

| Direct library | Build system | Effective dependency | Result |
|---|---|---|---|
| Apache Calcite 1.42.0 | Maven | commons-text 1.11.0 + commons-lang3 3.1 | Existing control reproduces the known Shady finding |
| Apache Calcite 1.42.0 | Gradle 9.7.1 | commons-text 1.11.0 + commons-lang3 3.18.0 | No hazard; Gradle's conflict resolution avoids the Maven failure |

This control confirms that each finding must be attributed to the concrete resolved graph rather
than to a library version in isolation.

## Test environment

- Eclipse Temurin JDK 21.0.12.1
- Gradle 9.7.1
- Maven 3.9.x
- Shady built from the current main branch

## Work queue

- [x] Establish the Maven/Gradle Calcite resolver control.
- [ ] Broad-scan current OSS dependency graphs, weighted toward Gradle.
- [ ] Triage every static signal for false positives and optional/dead code.
- [ ] Build minimal normal-API reproductions.
- [ ] Search upstream issue trackers and changelogs for duplicates.
- [ ] Commit verified fixtures and automated assertions.
- [ ] Record rejected candidates so the final result is auditable.

The evidence table will be updated as candidates are verified or rejected.
