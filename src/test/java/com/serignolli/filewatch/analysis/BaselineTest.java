package com.serignolli.filewatch.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.serignolli.filewatch.config.FileWatchProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static com.serignolli.filewatch.TestSupport.properties;
import static org.assertj.core.api.Assertions.assertThat;

class BaselineTest {

    @TempDir
    Path root;

    @Test
    void roundTripsThroughJsonPreservingMtimePrecision() {
        FileWatchProperties props = properties(root.resolve("sandbox"), root);
        Path file = root.resolve("sandbox").resolve("a.txt");
        BaselineEntry entry = new BaselineEntry(file, 42, Instant.parse("2026-09-23T12:34:56.123456700Z"), "ab".repeat(32), 4.25);

        Baseline original = new Baseline(props, new ObjectMapper());
        original.put(entry);
        original.save();

        Baseline reloaded = new Baseline(props, new ObjectMapper());
        reloaded.load();

        assertThat(reloaded.loadedFromDisk()).isTrue();
        assertThat(reloaded.get(file)).contains(entry);
    }

    @Test
    void corruptFileStartsEmptyInsteadOfCrashing() throws IOException {
        FileWatchProperties props = properties(root.resolve("sandbox"), root);
        Files.writeString(props.baselinePath(), "{ isto não é json");

        Baseline baseline = new Baseline(props, new ObjectMapper());
        baseline.load();

        assertThat(baseline.loadedFromDisk()).isFalse();
        assertThat(baseline.size()).isZero();
    }

    @Test
    void removeTreeRemovesADirectoryAndEverythingBelow() {
        Baseline baseline = new Baseline(properties(root.resolve("sandbox"), root), new ObjectMapper());
        Path dir = root.resolve("sandbox").resolve("docs");
        baseline.put(new BaselineEntry(dir.resolve("a.txt"), 1, Instant.EPOCH, "x", 1));
        baseline.put(new BaselineEntry(dir.resolve("sub/b.txt"), 1, Instant.EPOCH, "y", 1));
        baseline.put(new BaselineEntry(root.resolve("sandbox").resolve("docs-other.txt"), 1, Instant.EPOCH, "z", 1));

        assertThat(baseline.removeTree(dir)).hasSize(2);
        assertThat(baseline.size()).isEqualTo(1); // "docs-other.txt" não está sob "docs/"
    }
}
