package com.serignolli.filewatch.detection;

import com.serignolli.filewatch.TestSupport.MutableClock;
import com.serignolli.filewatch.analysis.FileAnalyzedEvent;
import com.serignolli.filewatch.watcher.ChangeType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static com.serignolli.filewatch.TestSupport.properties;
import static org.assertj.core.api.Assertions.assertThat;

class RansomwareDetectorTest {

    private final Path sandbox = Path.of("sandbox").toAbsolutePath();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-09-23T12:00:00Z"));
    private final List<RansomwareSuspectedEvent> alerts = new ArrayList<>();
    private RansomwareDetector detector;

    @BeforeEach
    void setUp() {
        // Limiares do application.yml: janela 10s, massa 30, spike 10, abs 7.5, delta 2.0, cooldown 30s.
        detector = new RansomwareDetector(properties(sandbox, sandbox),
                e -> alerts.add((RansomwareSuspectedEvent) e), clock);
    }

    private FileAnalyzedEvent event(String name, ChangeType type, double entropy, Double previous) {
        return new FileAnalyzedEvent(sandbox.resolve(name), type, 16_384, "h", entropy, previous, true, clock.instant());
    }

    private void feed(FileAnalyzedEvent e) {
        detector.onFileAnalyzed(e);
        clock.advance(Duration.ofMillis(50));
    }

    @Test
    void normalUseDoesNotAlert() {
        feed(event("notas.txt", ChangeType.MODIFIED, 4.6, 4.5));
        feed(event("planilha.csv", ChangeType.MODIFIED, 3.9, 3.8));
        feed(event("foto.jpg", ChangeType.CREATED, 7.9, null)); // alta entropia, mas sem baseline anterior

        assertThat(alerts).isEmpty();
    }

    @Test
    void simulatorPatternRaisesHighWithMultipleReasons() {
        for (int i = 0; i < 40; i++) {
            feed(event("relatorio-%03d.txt".formatted(i), ChangeType.MODIFIED, 7.98, 4.3));
        }
        for (int i = 0; i < 40; i++) {
            feed(event("relatorio-%03d.txt.encrypted".formatted(i), ChangeType.CREATED, 7.98, null));
        }
        feed(event("README_DECRYPT.txt", ChangeType.CREATED, 4.5, null));

        assertThat(alerts).anySatisfy(a -> {
            assertThat(a.severity()).isEqualTo(Severity.HIGH);
            assertThat(a.reasons()).hasSizeGreaterThanOrEqualTo(2);
            assertThat(a.involvedFiles()).isNotEmpty();
        });
    }

    @Test
    void singleSignalIsOnlyAWarning() {
        feed(event("backup.locked", ChangeType.CREATED, 5.0, null));

        assertThat(alerts).singleElement().satisfies(a -> {
            assertThat(a.severity()).isEqualTo(Severity.WARNING);
            assertThat(a.reasons()).singleElement().asString().startsWith("S3");
        });
    }

    @Test
    void ransomNoteAndSuspiciousExtensionTogetherAreHigh() {
        feed(event("HOW_TO_DECRYPT.html", ChangeType.CREATED, 4.8, null));
        feed(event("tese.docx.crypt", ChangeType.CREATED, 7.9, null));

        assertThat(alerts).last().satisfies(a -> assertThat(a.severity()).isEqualTo(Severity.HIGH));
    }

    @Test
    void cooldownSilencesAlertsAfterHighAndThenResumes() {
        feed(event("README_DECRYPT.txt", ChangeType.CREATED, 4.5, null));
        feed(event("a.enc", ChangeType.CREATED, 7.9, null));
        int afterHigh = alerts.size();
        assertThat(alerts).last().satisfies(a -> assertThat(a.severity()).isEqualTo(Severity.HIGH));

        feed(event("b.enc", ChangeType.CREATED, 7.9, null));
        feed(event("restore_files.txt", ChangeType.CREATED, 4.5, null));
        assertThat(alerts).hasSize(afterHigh);

        clock.advance(Duration.ofSeconds(31));
        feed(event("c.enc", ChangeType.CREATED, 7.9, null));
        feed(event("README_DECRYPT_2.txt", ChangeType.CREATED, 4.5, null));
        assertThat(alerts).hasSizeGreaterThan(afterHigh);
    }

    @Test
    void repeatedWarningWithSameSignalsIsNotSpammed() {
        for (int i = 0; i < 5; i++) {
            feed(event("x" + i + ".locked", ChangeType.CREATED, 5.0, null));
        }
        assertThat(alerts).hasSize(1);
    }

    @Test
    void eventsOlderThanTheWindowStopCounting() {
        for (int i = 0; i < 29; i++) {
            feed(event("f" + i + ".txt", ChangeType.MODIFIED, 4.6, 4.5));
        }
        clock.advance(Duration.ofSeconds(11)); // os 29 anteriores saem da janela
        feed(event("f29.txt", ChangeType.MODIFIED, 4.6, 4.5));

        assertThat(alerts).isEmpty();
    }
}
