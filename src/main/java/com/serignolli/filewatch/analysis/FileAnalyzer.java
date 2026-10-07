package com.serignolli.filewatch.analysis;

import com.serignolli.filewatch.config.AsyncConfig;
import com.serignolli.filewatch.config.FileWatchProperties;
import com.serignolli.filewatch.security.PathGuard;
import com.serignolli.filewatch.watcher.ChangeType;
import com.serignolli.filewatch.watcher.FileChangedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Reprocessa só o arquivo que mudou: hash SHA-256 por streaming + entropia amostrada,
 * compara com o baseline e publica {@link FileAnalyzedEvent} se o conteúdo mudou (SPEC §5.2).
 * <p>
 * Só <b>lê bytes</b>. Nunca executa, abre em programa externo ou altera o arquivo analisado.
 */
@Component
public class FileAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(FileAnalyzer.class);
    private static final int BUFFER_SIZE = 64 * 1024;

    private final PathGuard guard;
    private final Baseline baseline;
    private final ApplicationEventPublisher publisher;
    private final Clock clock;
    private final int samplingBytes;

    public record ScanSummary(int files, int cacheHits, int changed, int removed) {}

    private record Digest(long size, Instant mtime, String sha256, double entropy) {}

    public FileAnalyzer(PathGuard guard, Baseline baseline, ApplicationEventPublisher publisher,
                        FileWatchProperties properties, Clock clock) {
        this.guard = guard;
        this.baseline = baseline;
        this.publisher = publisher;
        this.clock = clock;
        this.samplingBytes = properties.samplingBytes();
    }

    /** Roda no pool {@code analyzer-*}: a thread do watcher nunca espera por hash. */
    @Async(AsyncConfig.ANALYSIS_EXECUTOR)
    @EventListener
    public void onFileChanged(FileChangedEvent event) {
        try {
            analyze(event.path(), event.type()).forEach(publisher::publishEvent);
        } catch (RuntimeException e) {
            log.error("Falha analisando {}", event.path(), e);
        }
    }

    // Listener void de propósito: um @EventListener que retorna valor tem o retorno republicado como evento.
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        initialScan();
    }

    /**
     * Varredura incremental no start (SPEC §5.3): o que tem mesmo tamanho e mtime do baseline
     * é "cache hit" e não é re-hasheado. Na primeira execução (sem baseline no disco) só
     * constrói o baseline, sem alimentar o detector — senão todo arquivo seria "novo" e
     * dispararia modificação em massa.
     */
    public ScanSummary initialScan() {
        boolean publish = baseline.loadedFromDisk();
        List<Path> files = listFiles(guard.base());
        Set<Path> seen = new HashSet<>();
        int cacheHits = 0;
        int changed = 0;
        int removed = 0;

        for (Path file : files) {
            seen.add(file);
            Optional<BaselineEntry> previous = baseline.get(file);
            if (previous.isPresent() && sameMetadata(previous.get(), file)) {
                cacheHits++;
                log.debug("cache hit (tamanho+mtime iguais, sem re-hash): {}", file);
                continue;
            }
            List<FileAnalyzedEvent> events = analyze(file, previous.isPresent() ? ChangeType.MODIFIED : ChangeType.CREATED);
            changed += events.size();
            if (publish) {
                events.forEach(publisher::publishEvent);
            }
        }
        for (Path known : baseline.paths()) {
            if (!seen.contains(known)) {
                List<FileAnalyzedEvent> events = analyze(known, ChangeType.DELETED);
                removed += events.size();
                if (publish) {
                    events.forEach(publisher::publishEvent);
                }
            }
        }

        ScanSummary summary = new ScanSummary(files.size(), cacheHits, changed, removed);
        log.info("Varredura inicial{}: {} arquivos, {} cache hits, {} novos/alterados, {} removidos",
                publish ? "" : " (criando baseline)", summary.files(), summary.cacheHits(), summary.changed(), summary.removed());
        baseline.save();
        return summary;
    }

    /** Analisa um path. Lista vazia = nada a reportar (fora do sandbox, não é arquivo, ou hash igual). */
    public List<FileAnalyzedEvent> analyze(Path candidate, ChangeType type) {
        if (Files.isSymbolicLink(candidate)) {
            log.debug("Ignorando symlink {}", candidate);
            return List.of();
        }
        Optional<Path> inside = guard.resolveInside(candidate);
        if (inside.isEmpty()) {
            return List.of();
        }
        Path path = inside.get();

        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return handleDeleted(path);
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();
        }
        ChangeType effectiveType = type == ChangeType.DELETED ? ChangeType.MODIFIED : type; // voltou a existir

        Digest digest;
        try {
            digest = digest(path);
        } catch (IOException e) {
            // Comum no Windows: arquivo ainda aberto por quem escreve. O próximo MODIFY tenta de novo.
            log.debug("Não foi possível ler {} agora: {}", path, e.toString());
            return List.of();
        }

        Optional<BaselineEntry> previous = baseline.get(path);
        baseline.put(new BaselineEntry(path, digest.size(), digest.mtime(), digest.sha256(), digest.entropy()));

        if (previous.isPresent() && previous.get().sha256().equals(digest.sha256())) {
            log.debug("cache hit (hash igual, só metadados mudaram): {}", path);
            return List.of();
        }

        FileAnalyzedEvent event = new FileAnalyzedEvent(
                path,
                effectiveType,
                digest.size(),
                digest.sha256(),
                digest.entropy(),
                previous.map(BaselineEntry::entropy).orElse(null),
                true,
                clock.instant());
        log.debug("Analisado {} {}: entropia {} (antes {})", effectiveType, path,
                String.format("%.2f", event.entropy()), event.previousEntropy());
        return List.of(event);
    }

    private List<FileAnalyzedEvent> handleDeleted(Path path) {
        Instant now = clock.instant();
        return baseline.removeTree(path).stream()
                .map(e -> new FileAnalyzedEvent(e.path(), ChangeType.DELETED, 0, null, 0.0, e.entropy(), true, now))
                .toList();
    }

    /** Uma única leitura em blocos alimenta o SHA-256 (arquivo inteiro) e a entropia (primeiros samplingBytes). */
    private Digest digest(Path path) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        MessageDigest sha = sha256();
        EntropyCalculator entropy = new EntropyCalculator(samplingBytes);
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                sha.update(buffer, 0, read);
                if (!entropy.isSaturated()) {
                    entropy.update(buffer, 0, read);
                }
            }
        }
        return new Digest(attrs.size(), attrs.lastModifiedTime().toInstant(),
                HexFormat.of().formatHex(sha.digest()), entropy.entropy());
    }

    private static boolean sameMetadata(BaselineEntry entry, Path file) {
        try {
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return attrs.size() == entry.size() && attrs.lastModifiedTime().toInstant().equals(entry.mtime());
        } catch (IOException e) {
            return false;
        }
    }

    private static List<Path> listFiles(Path root) {
        List<Path> files = new ArrayList<>();
        try {
            // walkFileTree não segue symlinks por padrão: não sai do sandbox por link.
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (attrs.isRegularFile()) {
                        files.add(file);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException e) {
                    log.debug("Ignorando {}: {}", file, e.toString());
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.error("Falha na varredura de {}", root, e);
        }
        return files;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível na JVM", e);
        }
    }
}
