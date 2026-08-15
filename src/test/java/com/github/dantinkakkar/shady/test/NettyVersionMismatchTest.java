package com.github.dantinkakkar.shady.test;

import com.github.dantinkakkar.shady.LinkageHazardDetector;
import com.github.dantinkakkar.shady.LinkageHazardDetector.LinkageHazard;
import io.netty.handler.codec.compression.ZlibCodecFactory;
import io.netty.handler.codec.http.HttpContentDecompressor;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class NettyVersionMismatchTest {

    private static final String TARGET =
            "io.netty.handler.codec.compression.ZlibCodecFactory";
    private static final String MISSING_METHOD =
            "newZlibDecoder(Lio/netty/handler/codec/compression/ZlibWrapper;I)"
                    + "Lio/netty/handler/codec/compression/ZlibDecoder;";
    private static final String CALLER =
            "io.netty.handler.codec.http.HttpContentDecompressor"
                    + ".newContentDecoder(Ljava/lang/String;)"
                    + "Lio/netty/channel/embedded/EmbeddedChannel;";

    @Test
    void catchesTheOriginalSpringBootNettyMismatch() throws URISyntaxException {
        Path codecHttp = codeSourceOf(HttpContentDecompressor.class);
        Path codec = codeSourceOf(ZlibCodecFactory.class);

        // Guard the fixture itself: this must be the dependency graph that failed in production.
        assertEquals("netty-codec-http-4.1.125.Final.jar", codecHttp.getFileName().toString());
        assertEquals("netty-codec-4.1.119.Final.jar", codec.getFileName().toString());

        LinkageHazardDetector detector = new LinkageHazardDetector();
        detector.scanClasspath(codecHttp + File.pathSeparator + codec);

        assertFalse(detector.getDuplicateClasses().containsKey(TARGET),
                "This is a cross-artifact ABI mismatch, not a duplicate-class conflict");

        LinkageHazard hazard = detector.getDetectedHazards().stream()
                .filter(candidate -> TARGET.equals(candidate.getTargetClassName()))
                .filter(candidate -> MISSING_METHOD.equals(candidate.getMethodSignature()))
                .filter(candidate -> CALLER.equals(candidate.getCallerSignature()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Shady did not catch the exact Netty mismatch; hazards were "
                                + detector.getDetectedHazards()));

        assertEquals(codec.toAbsolutePath().normalize().toString(), hazard.getTargetLocation());
    }

    private static Path codeSourceOf(Class<?> type) throws URISyntaxException {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toAbsolutePath()
                .normalize();
    }
}
