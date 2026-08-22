plugins {
    java
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

application {
    mainClass.set("shady.example.GradleJacksonApp")
}

repositories {
    mavenCentral()
}

dependencies {
    /*
     * jackson-databind 2.18.3 is a direct dependency that transitively requires
     * jackson-core 2.18.3.  The resolutionStrategy below forces jackson-core down
     * to 2.15.4, reproducing the incompatibility that arises in real applications
     * whose dependency graph includes a library that pins jackson-core at 2.15.x
     * (for example via a Spring Boot 3.2.x enforced BOM or a Gradle version catalog
     * entry with a strict version constraint).  The result: ObjectMapper calls
     * BufferRecycler.releaseToPool(), a method absent from jackson-core 2.15.x,
     * and throws NoSuchMethodError at runtime.
     */
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.3")
}

configurations.all {
    resolutionStrategy {
        force("com.fasterxml.jackson.core:jackson-core:2.15.4")
        force("com.fasterxml.jackson.core:jackson-annotations:2.15.4")
    }
}

/*
 * Write the resolved runtime classpath to a file so the regression test can
 * hand it directly to the Shady agent without parsing Gradle's text output.
 */
tasks.register("writeRuntimeClasspath") {
    val outputFile = layout.buildDirectory.file("runtime-classpath.txt")
    outputs.file(outputFile)
    dependsOn(configurations.runtimeClasspath)
    doLast {
        val cp = configurations.runtimeClasspath.get()
            .resolvedConfiguration
            .resolvedArtifacts
            .joinToString(File.pathSeparator) { it.file.absolutePath }
        outputFile.get().asFile.writeText(cp)
    }
}
