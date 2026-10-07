package com.serignolli.filewatch.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Mapeamento de {@code filewatch.*} do application.yml.
 * <p>
 * Os caminhos são lidos como String e convertidos aqui com {@link Path#of}, de propósito:
 * o conversor padrão de Path do Spring tenta resolver como Resource (inclusive classpath),
 * o que é ambíguo demais para a pasta que define o sandbox.
 * <p>
 * {@code requireSandboxMarker} (padrão {@code true}) faz o monitor só aceitar uma pasta que contenha
 * o marcador {@code .filewatch-sandbox}, o mesmo exigido pelo simulador. Assim, um
 * {@code --filewatch.monitored-path} digitado errado não passa a observar pastas reais.
 */
@ConfigurationProperties(prefix = "filewatch")
public record FileWatchProperties(
        @DefaultValue("./sandbox") String monitoredPath,
        @DefaultValue("./baseline.json") String baselineFile,
        @DefaultValue("./alerts.log") String alertsFile,
        @DefaultValue("262144") int samplingBytes,
        @DefaultValue("300") long debounceMillis,
        @DefaultValue Detection detection,
        @DefaultValue({".locked", ".encrypted", ".crypt", ".enc"}) List<String> suspiciousExtensions,
        @DefaultValue({"(?i)readme.*decrypt", "(?i)how.*to.*decrypt", "(?i)restore.*files"}) List<String> ransomNotePatterns,
        @DefaultValue("true") boolean requireSandboxMarker) {

    public record Detection(
            @DefaultValue("10") long windowSeconds,
            @DefaultValue("30") int massModificationThreshold,
            @DefaultValue("10") int entropySpikeCount,
            @DefaultValue("7.5") double entropyAbsoluteMin,
            @DefaultValue("2.0") double entropyDeltaMin,
            @DefaultValue("30") long alertCooldownSeconds) {

        public Duration window() {
            return Duration.ofSeconds(windowSeconds);
        }

        public Duration alertCooldown() {
            return Duration.ofSeconds(alertCooldownSeconds);
        }
    }

    public Path monitoredDir() {
        return Path.of(monitoredPath);
    }

    public Path baselinePath() {
        return Path.of(baselineFile);
    }

    public Path alertsPath() {
        return Path.of(alertsFile);
    }

    public Duration debounce() {
        return Duration.ofMillis(debounceMillis);
    }
}
