package shady.example;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A normal application that serialises a plain object with Jackson.
 *
 * <p>When run with the Shady agent and an incompatible dependency graph
 * (jackson-databind 2.18.x + jackson-core 2.15.x via an enforced Spring Boot
 * 3.2.x BOM), Shady reports the hazard before
 * {@link ObjectMapper#writeValueAsString} is reached and the JVM throws
 * {@code NoSuchMethodError: BufferRecycler.releaseToPool()}.
 */
public final class GradleJacksonApp {
    private GradleJacksonApp() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("GRADLE_JACKSON_APP_STARTED");
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(new Payload("Shady finds regressions", 42));
        System.out.println("JACKSON_RESULT=" + json);
    }

    public static final class Payload {
        public final String message;
        public final int value;

        public Payload(String message, int value) {
            this.message = message;
            this.value = value;
        }
    }
}
