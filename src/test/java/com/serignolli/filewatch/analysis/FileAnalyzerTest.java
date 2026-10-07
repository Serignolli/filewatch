package com.serignolli.filewatch.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.serignolli.filewatch.config.FileWatchProperties;
import com.serignolli.filewatch.security.PathGuard;
import com.serignolli.filewatch.watcher.ChangeType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static com.serignolli.filewatch.TestSupport.properties;
import static org.assertj.core.api.Assertions.assertThat;

class FileAnalyzerTest {

    private static final String TEXT = "Relatório trimestral: receitas, despesas e observações gerais. ".repeat(300);

    @TempDir
    Path root;

    Path sandbox;
    FileWatchProperties props;
    PathGuard guard;
    Baseline baseline;
    FileAnalyzer analyzer;
    List<Object> published = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() throws IOException {
        sandbox = Files.createDirectories(root.resolve("sandbox"));
        props = properties(sandbox, root);
        guard = new PathGuard(props);
        baseline = new Baseline(props, new ObjectMapper());
        baseline.load();
        analyzer = newAnalyzer(baseline);
    }

    private FileAnalyzer newAnalyzer(Baseline b) {
        return new FileAnalyzer(guard, b, published::add, props, Clock.systemUTC());
    }

    @Test
    void newTextFileIsReportedWithLowEntropyAndNoPrevious() throws IOException {
        Path file = Files.writeString(sandbox.resolve("doc.txt"), TEXT);

        List<FileAnalyzedEvent> events = analyzer.analyze(file, ChangeType.CREATED);

        assertThat(events).singleElement().satisfies(e -> {
            assertThat(e.contentChanged()).isTrue();
            assertThat(e.previousEntropy()).isNull();
            assertThat(e.entropy()).isBetween(3.5, 5.5);
            assertThat(e.sha256()).hasSize(64);
        });
    }

    @Test
    void sameContentIsACacheHit() throws IOException {
        Path file = Files.writeString(sandbox.resolve("doc.txt"), TEXT);
        analyzer.analyze(file, ChangeType.CREATED);

        Files.writeString(file, TEXT); // mesmo conteúdo, mtime novo
        assertThat(analyzer.analyze(file, ChangeType.MODIFIED)).isEmpty();
    }

    @Test
    void textOverwrittenWithRandomBytesJumpsAboveSevenAndAHalf() throws IOException {
        Path file = Files.writeString(sandbox.resolve("doc.txt"), TEXT);
        analyzer.analyze(file, ChangeType.CREATED);

        byte[] noise = new byte[64 * 1024];
        new SecureRandom().nextBytes(noise);
        Files.write(file, noise);

        assertThat(analyzer.analyze(file, ChangeType.MODIFIED)).singleElement().satisfies(e -> {
            assertThat(e.entropy()).isGreaterThan(7.5);
            assertThat(e.previousEntropy()).isLessThan(5.5);
            assertThat(e.contentChanged()).isTrue();
        });
    }

    @Test
    void filesOutsideTheSandboxAreIgnored() throws IOException {
        Path outside = Files.writeString(root.resolve("outside.txt"), TEXT);

        assertThat(analyzer.analyze(outside, ChangeType.CREATED)).isEmpty();
        assertThat(analyzer.analyze(sandbox.resolve("../outside.txt"), ChangeType.CREATED)).isEmpty();
        assertThat(baseline.size()).isZero();
    }

    @Test
    void deletionOfKnownFileIsReportedAndRemovedFromBaseline() throws IOException {
        Path file = Files.writeString(sandbox.resolve("doc.txt"), TEXT);
        analyzer.analyze(file, ChangeType.CREATED);
        Files.delete(file);

        assertThat(analyzer.analyze(file, ChangeType.DELETED)).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo(ChangeType.DELETED);
            assertThat(e.contentChanged()).isTrue();
        });
        assertThat(baseline.size()).isZero();
        assertThat(analyzer.analyze(file, ChangeType.DELETED)).isEmpty(); // desconhecido: nada a reportar
    }

    @Test
    void secondStartDoesNotRehashUnchangedFiles() throws IOException {
        for (int i = 0; i < 5; i++) {
            Files.writeString(sandbox.resolve("f" + i + ".txt"), TEXT + i);
        }

        FileAnalyzer.ScanSummary first = analyzer.initialScan(); // cria e salva o baseline
        assertThat(first.changed()).isEqualTo(5);
        assertThat(published).as("primeira execução só cria o baseline").isEmpty();

        Baseline reloaded = new Baseline(props, new ObjectMapper());
        reloaded.load();
        assertThat(reloaded.loadedFromDisk()).isTrue();

        FileAnalyzer.ScanSummary second = newAnalyzer(reloaded).initialScan();
        assertThat(second.cacheHits()).isEqualTo(5);
        assertThat(second.changed()).isZero();
        assertThat(second.removed()).isZero();
    }

    @Test
    void secondStartReportsWhatChangedWhileOffline() throws IOException {
        Path keep = Files.writeString(sandbox.resolve("keep.txt"), TEXT);
        Path change = Files.writeString(sandbox.resolve("change.txt"), TEXT);
        Path remove = Files.writeString(sandbox.resolve("remove.txt"), TEXT);
        analyzer.initialScan();

        Files.writeString(change, TEXT + "alterado");
        Files.delete(remove);
        Files.writeString(sandbox.resolve("new.txt"), TEXT);

        Baseline reloaded = new Baseline(props, new ObjectMapper());
        reloaded.load();
        FileAnalyzer.ScanSummary summary = newAnalyzer(reloaded).initialScan();

        assertThat(summary.cacheHits()).isEqualTo(1); // keep.txt
        assertThat(summary.changed()).isEqualTo(2);   // change.txt + new.txt
        assertThat(summary.removed()).isEqualTo(1);
        assertThat(published).hasSize(3);
        assertThat(reloaded.get(keep.toRealPath())).isPresent();
    }
}
