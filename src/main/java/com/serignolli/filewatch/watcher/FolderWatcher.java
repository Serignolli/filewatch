package com.serignolli.filewatch.watcher;

import com.serignolli.filewatch.config.FileWatchProperties;
import com.serignolli.filewatch.security.PathGuard;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

/**
 * Observa a pasta monitorada e publica {@link FileChangedEvent} (SPEC §5.1).
 * <p>
 * Duas threads, nenhuma faz hash:
 * <ul>
 *   <li>{@code folder-watcher}: loop de {@code watchService.take()}; só anota o evento no mapa de pendentes.</li>
 *   <li>{@code watch-debounce}: a cada poucos ms publica os paths que ficaram quietos por {@code debounce-millis}.</li>
 * </ul>
 * O {@code WatchService} não é recursivo: cada subdiretório é registrado no start e,
 * quando um diretório novo aparece, ele (e o que já houver dentro) é registrado na hora.
 */
@Component
public class FolderWatcher {

    private static final Logger log = LoggerFactory.getLogger(FolderWatcher.class);

    private final PathGuard guard;
    private final ApplicationEventPublisher publisher;
    private final Duration debounce;
    private final Clock clock;

    private final Map<WatchKey, Path> keys = new ConcurrentHashMap<>();
    private final Map<Path, Pending> pending = new ConcurrentHashMap<>();

    private WatchService watchService;
    private ExecutorService loop;
    private ScheduledExecutorService flusher;
    private volatile boolean running;

    private record Pending(ChangeType type, Instant lastSeen) {}

    public FolderWatcher(PathGuard guard, ApplicationEventPublisher publisher,
                         FileWatchProperties properties, Clock clock) {
        this.guard = guard;
        this.publisher = publisher;
        this.debounce = properties.debounce();
        this.clock = clock;
    }

    @PostConstruct
    void start() throws IOException {
        watchService = FileSystems.getDefault().newWatchService();
        registerTree(guard.base(), null);
        running = true;

        // Thread não-daemon: é ela que mantém a aplicação (sem web) viva.
        loop = Executors.newSingleThreadExecutor(named("folder-watcher", false));
        loop.submit(this::watchLoop);

        long period = Math.max(20, debounce.toMillis() / 3);
        flusher = Executors.newSingleThreadScheduledExecutor(named("watch-debounce", true));
        flusher.scheduleWithFixedDelay(this::flush, period, period, TimeUnit.MILLISECONDS);

        log.info("Observando {} ({} diretórios registrados, debounce {} ms)",
                guard.base(), keys.size(), debounce.toMillis());
    }

    @PreDestroy
    void stop() {
        running = false;
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException e) {
            log.warn("Erro ao fechar WatchService", e);
        }
        if (loop != null) {
            loop.shutdownNow();
        }
        if (flusher != null) {
            flusher.shutdownNow();
        }
    }

    private void watchLoop() {
        while (running) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }
            Path dir = keys.get(key);
            if (dir == null) {
                key.cancel();
                continue;
            }
            for (WatchEvent<?> event : key.pollEvents()) {
                try {
                    handle(dir, event);
                } catch (RuntimeException e) {
                    log.error("Erro tratando evento {} em {}", event.kind(), dir, e);
                }
            }
            if (!key.reset()) {
                keys.remove(key); // diretório removido ou inacessível
            }
        }
        log.info("Watcher encerrado");
    }

    private void handle(Path dir, WatchEvent<?> event) {
        if (event.kind() == OVERFLOW) {
            // O SO descartou eventos (rajada grande demais). Re-varre o diretório: o analyzer
            // compara hash com o baseline, então o que não mudou sai como cache hit.
            // Remoções perdidas aqui só são reconciliadas no próximo start.
            log.warn("OVERFLOW em {}: eventos perdidos pelo SO, re-varrendo", dir);
            registerTree(dir, ChangeType.MODIFIED);
            return;
        }
        Path child = dir.resolve((Path) event.context());
        ChangeType type = toChangeType(event.kind());

        if (type == ChangeType.DELETED) {
            record(child, type);
            return;
        }
        if (!guard.isInside(child)) {
            return;
        }
        if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) {
            if (type == ChangeType.CREATED) {
                // Arquivos criados antes do registro não geram evento: registerTree os emite.
                registerTree(child, ChangeType.CREATED);
            }
            return; // MODIFY de diretório é só "o conteúdo mudou"; os arquivos têm seus próprios eventos
        }
        record(child, type);
    }

    /** Registra {@code start} e todos os subdiretórios; se {@code emitFiles} != null, emite esse tipo para cada arquivo encontrado. */
    private void registerTree(Path start, ChangeType emitFiles) {
        try {
            Files.walkFileTree(start, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (!guard.isInside(dir)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    try {
                        WatchKey key = dir.register(watchService, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);
                        keys.put(key, dir);
                    } catch (IOException e) {
                        log.warn("Não foi possível registrar {}: {}", dir, e.toString());
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (emitFiles != null && attrs.isRegularFile()) {
                        record(file, emitFiles);
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
            log.warn("Falha ao percorrer {}: {}", start, e.toString());
        }
    }

    /** Debounce: anota o último evento do path; o flush publica quando ele sossegar. */
    private void record(Path path, ChangeType type) {
        Pending incoming = new Pending(type, clock.instant());
        pending.merge(path, incoming, (old, neu) -> new Pending(merge(old.type(), neu.type()), neu.lastSeen()));
    }

    private static ChangeType merge(ChangeType previous, ChangeType latest) {
        if (latest == ChangeType.DELETED) {
            return ChangeType.DELETED;
        }
        if (previous == ChangeType.CREATED) {
            return ChangeType.CREATED; // criado e depois escrito = ainda "criado"
        }
        if (previous == ChangeType.DELETED) {
            return ChangeType.MODIFIED; // apagado e recriado = substituído
        }
        return latest;
    }

    private void flush() {
        // Exceção aqui mataria o agendamento: por isso o catch amplo.
        try {
            Instant cutoff = clock.instant().minus(debounce);
            for (Map.Entry<Path, Pending> entry : pending.entrySet()) {
                Pending p = entry.getValue();
                if (p.lastSeen().isBefore(cutoff) && pending.remove(entry.getKey(), p)) {
                    publisher.publishEvent(new FileChangedEvent(entry.getKey(), p.type(), p.lastSeen()));
                }
            }
        } catch (RuntimeException e) {
            log.error("Erro no flush do debounce", e);
        }
    }

    private static ChangeType toChangeType(WatchEvent.Kind<?> kind) {
        if (kind == ENTRY_CREATE) {
            return ChangeType.CREATED;
        }
        if (kind == ENTRY_DELETE) {
            return ChangeType.DELETED;
        }
        return ChangeType.MODIFIED;
    }

    private static ThreadFactory named(String name, boolean daemon) {
        return runnable -> {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(daemon);
            return thread;
        };
    }
}
