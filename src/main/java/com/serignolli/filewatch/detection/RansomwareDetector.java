package com.serignolli.filewatch.detection;

import com.serignolli.filewatch.analysis.FileAnalyzedEvent;
import com.serignolli.filewatch.config.FileWatchProperties;
import com.serignolli.filewatch.watcher.ChangeType;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Detector comportamental (SPEC §5.4). Mantém uma janela deslizante de {@link FileAnalyzedEvent}
 * e avalia quatro sinais:
 * <ul>
 *   <li>S1 — modificação em massa</li>
 *   <li>S2 — salto de entropia (arquivo virou "ruído aleatório")</li>
 *   <li>S3 — extensão suspeita</li>
 *   <li>S4 — nota de resgate</li>
 * </ul>
 * 1 sinal → WARNING; 2+ sinais distintos → HIGH. Após um HIGH, silencia alertas por um cooldown.
 * Um WARNING com exatamente os mesmos sinais do anterior também é silenciado no cooldown,
 * senão cada evento dentro da janela repetiria o mesmo aviso. Escalar para HIGH nunca é silenciado
 * por um WARNING.
 */
@Component
public class RansomwareDetector {

    enum Signal { MASS_MODIFICATION, ENTROPY_SPIKE, SUSPICIOUS_EXTENSION, RANSOM_NOTE }

    private final FileWatchProperties.Detection config;
    private final List<String> suspiciousExtensions;
    private final List<Pattern> ransomNotePatterns;
    private final ApplicationEventPublisher publisher;
    private final Clock clock;
    private final DetectionWindow window;

    private Instant lastHighAt;
    private Instant lastWarningAt;
    private Set<Signal> lastWarningSignals = Set.of();

    public RansomwareDetector(FileWatchProperties properties, ApplicationEventPublisher publisher, Clock clock) {
        this.config = properties.detection();
        this.suspiciousExtensions = properties.suspiciousExtensions().stream()
                .map(ext -> ext.toLowerCase(Locale.ROOT))
                .toList();
        this.ransomNotePatterns = properties.ransomNotePatterns().stream().map(Pattern::compile).toList();
        this.publisher = publisher;
        this.clock = clock;
        this.window = new DetectionWindow(config.window());
    }

    @EventListener
    public void onFileAnalyzed(FileAnalyzedEvent event) {
        // Avalia sob lock, mas publica fora dele: o AlertListener faz I/O.
        evaluate(event).ifPresent(publisher::publishEvent);
    }

    synchronized Optional<RansomwareSuspectedEvent> evaluate(FileAnalyzedEvent event) {
        Instant now = clock.instant();
        window.add(event);
        window.prune(now);
        List<FileAnalyzedEvent> recent = window.snapshot();

        EnumSet<Signal> signals = EnumSet.noneOf(Signal.class);
        List<String> reasons = new ArrayList<>();
        Set<Path> involved = new LinkedHashSet<>();
        long windowSeconds = config.window().toSeconds();

        Set<Path> changed = paths(recent, FileAnalyzedEvent::contentChanged);
        if (changed.size() >= config.massModificationThreshold()) {
            signals.add(Signal.MASS_MODIFICATION);
            reasons.add("S1 modificação em massa: %d arquivos alterados em %ds (limiar %d)"
                    .formatted(changed.size(), windowSeconds, config.massModificationThreshold()));
            involved.addAll(changed);
        }

        Set<Path> spiked = paths(recent, this::isEntropySpike);
        if (spiked.size() >= config.entropySpikeCount()) {
            signals.add(Signal.ENTROPY_SPIKE);
            reasons.add("S2 salto de entropia: %d arquivos foram para >= %.1f bits/byte (+%.1f ou mais) em %ds (limiar %d)"
                    .formatted(spiked.size(), config.entropyAbsoluteMin(), config.entropyDeltaMin(),
                            windowSeconds, config.entropySpikeCount()));
            involved.addAll(spiked);
        }

        Set<Path> badExtension = paths(recent, e -> e.type() != ChangeType.DELETED && hasSuspiciousExtension(e.path()));
        if (!badExtension.isEmpty()) {
            signals.add(Signal.SUSPICIOUS_EXTENSION);
            reasons.add("S3 extensão suspeita: %d arquivo(s), ex.: %s"
                    .formatted(badExtension.size(), badExtension.iterator().next().getFileName()));
            involved.addAll(badExtension);
        }

        Set<Path> notes = paths(recent, e -> e.type() != ChangeType.DELETED && looksLikeRansomNote(e.path()));
        if (!notes.isEmpty()) {
            signals.add(Signal.RANSOM_NOTE);
            reasons.add("S4 possível nota de resgate: %s".formatted(notes.iterator().next().getFileName()));
            involved.addAll(notes);
        }

        if (signals.isEmpty()) {
            return Optional.empty();
        }
        Severity severity = signals.size() >= 2 ? Severity.HIGH : Severity.WARNING;
        if (isSuppressed(severity, signals, now)) {
            return Optional.empty();
        }
        if (severity == Severity.HIGH) {
            lastHighAt = now;
        } else {
            lastWarningAt = now;
            lastWarningSignals = Set.copyOf(signals);
        }
        return Optional.of(new RansomwareSuspectedEvent(severity, List.copyOf(reasons), List.copyOf(involved), now));
    }

    private boolean isSuppressed(Severity severity, Set<Signal> signals, Instant now) {
        if (lastHighAt != null && now.isBefore(lastHighAt.plus(config.alertCooldown()))) {
            return true;
        }
        return severity == Severity.WARNING
                && lastWarningAt != null
                && now.isBefore(lastWarningAt.plus(config.alertCooldown()))
                && signals.equals(lastWarningSignals);
    }

    private boolean isEntropySpike(FileAnalyzedEvent e) {
        return e.type() != ChangeType.DELETED
                && e.previousEntropy() != null
                && e.entropy() >= config.entropyAbsoluteMin()
                && e.entropy() - e.previousEntropy() >= config.entropyDeltaMin();
    }

    private boolean hasSuspiciousExtension(Path path) {
        String name = fileName(path).toLowerCase(Locale.ROOT);
        return suspiciousExtensions.stream().anyMatch(name::endsWith);
    }

    private boolean looksLikeRansomNote(Path path) {
        String name = fileName(path);
        return ransomNotePatterns.stream().anyMatch(p -> p.matcher(name).find());
    }

    private static Set<Path> paths(List<FileAnalyzedEvent> events, Predicate<FileAnalyzedEvent> filter) {
        Set<Path> result = new LinkedHashSet<>();
        for (FileAnalyzedEvent e : events) {
            if (filter.test(e)) {
                result.add(e.path());
            }
        }
        return result;
    }

    private static String fileName(Path path) {
        Path name = path.getFileName();
        return name == null ? "" : name.toString();
    }
}
