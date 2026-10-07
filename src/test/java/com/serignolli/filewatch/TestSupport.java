package com.serignolli.filewatch;

import com.serignolli.filewatch.config.FileWatchProperties;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Utilidades de teste. Os testes nunca sobem o contexto Spring (que observaria ./sandbox):
 * montam os componentes à mão apontando para um @TempDir.
 */
public final class TestSupport {

    private TestSupport() {
    }

    public static FileWatchProperties properties(Path sandbox, Path stateDir) {
        return properties(sandbox, stateDir, 300);
    }

    public static FileWatchProperties properties(Path sandbox, Path stateDir, long debounceMillis) {
        return new FileWatchProperties(
                sandbox.toString(),
                stateDir.resolve("baseline.json").toString(),
                stateDir.resolve("alerts.log").toString(),
                262_144,
                debounceMillis,
                new FileWatchProperties.Detection(10, 30, 10, 7.5, 2.0, 30),
                List.of(".locked", ".encrypted", ".crypt", ".enc"),
                List.of("(?i)readme.*decrypt", "(?i)how.*to.*decrypt", "(?i)restore.*files"),
                false);
    }

    /** Igual a {@link #properties(Path, Path)}, mas exigindo o marcador do sandbox como em produção. */
    public static FileWatchProperties propertiesRequiringMarker(Path sandbox, Path stateDir) {
        FileWatchProperties p = properties(sandbox, stateDir);
        return new FileWatchProperties(p.monitoredPath(), p.baselineFile(), p.alertsFile(), p.samplingBytes(),
                p.debounceMillis(), p.detection(), p.suspiciousExtensions(), p.ransomNotePatterns(), true);
    }

    /** Relógio controlável para testar janela e cooldown sem sleep. */
    public static final class MutableClock extends Clock {
        private Instant now;

        public MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
