package com.serignolli.filewatch.watcher;

import com.serignolli.filewatch.security.PathGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import static com.serignolli.filewatch.TestSupport.properties;
import static org.assertj.core.api.Assertions.assertThat;

/** Usa o WatchService real sobre um @TempDir. Timeouts generosos para não ficar instável. */
class FolderWatcherTest {

    @TempDir
    Path root;

    Path sandbox;
    FolderWatcher watcher;
    List<FileChangedEvent> events = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() throws IOException {
        sandbox = Files.createDirectories(root.resolve("sandbox"));
        var props = properties(sandbox, root, 100);
        watcher = new FolderWatcher(new PathGuard(props), e -> events.add((FileChangedEvent) e), props, Clock.systemUTC());
        watcher.start();
    }

    @AfterEach
    void tearDown() {
        watcher.stop();
    }

    @Test
    void burstOfWritesIsNotLost() throws IOException {
        int count = 200;
        for (int i = 0; i < count; i++) {
            Files.writeString(sandbox.resolve("burst-" + i + ".txt"), "conteúdo " + i);
        }

        awaitTrue(() -> distinctPaths().size() >= count);
        assertThat(distinctPaths()).hasSize(count);
    }

    @Test
    void debounceCollapsesRepeatedWritesIntoOneEvent() throws IOException {
        Path file = sandbox.resolve("salvo-varias-vezes.txt");
        for (int i = 0; i < 10; i++) {
            Files.writeString(file, "versão " + i);
        }

        awaitTrue(() -> !events.isEmpty());
        sleepQuietly(500); // dá tempo de algum evento duplicado aparecer, se houvesse
        assertThat(events).singleElement().satisfies(e -> assertThat(e.type()).isEqualTo(ChangeType.CREATED));
    }

    @Test
    void newSubdirectoriesAreWatchedRecursively() throws IOException {
        Path deep = Files.createDirectories(sandbox.resolve("a/b/c"));
        Files.writeString(deep.resolve("inside.txt"), "x");
        awaitTrue(() -> distinctPaths().stream().anyMatch(p -> p.endsWith("inside.txt")));

        // arquivo criado depois do registro também precisa ser visto
        Files.writeString(deep.resolve("later.txt"), "y");
        awaitTrue(() -> distinctPaths().stream().anyMatch(p -> p.endsWith("later.txt")));
    }

    @Test
    void deletionsAreReported() throws IOException {
        Path file = Files.writeString(sandbox.resolve("temp.txt"), "x");
        awaitTrue(() -> !events.isEmpty());

        Files.delete(file);
        awaitTrue(() -> events.stream().anyMatch(e -> e.type() == ChangeType.DELETED));
    }

    private Set<Path> distinctPaths() {
        return events.stream().map(FileChangedEvent::path).collect(Collectors.toSet());
    }

    private static void awaitTrue(BooleanSupplier condition) {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(15));
        while (!condition.getAsBoolean()) {
            if (Instant.now().isAfter(deadline)) {
                throw new AssertionError("Condição não satisfeita em 15s");
            }
            sleepQuietly(50);
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
